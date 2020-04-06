import copy
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

from airiam.models.RuntimeReport import RuntimeReport

IAM_DATA_FILE_NAME = "iam_data.json"
ERASE_LINE = '\x1b[2K'


class RuntimeIamScanner:
    """
    This class encapsulates all Runtime IAM data capture & classification
    It's entry point is the method `evaluate_runtime_iam`
    """

    def __init__(self, logger, profile=None, refresh_cache=False):
        self.logger = logger
        self.refresh_cache = refresh_cache
        if profile:
            self._session = boto3.Session(profile_name=profile)
        else:
            self._session = boto3.Session()

    def evaluate_runtime_iam(self, list_unused: bool) -> RuntimeReport:
        """
        This method encapsulates all Runtime IAM data capture & classification
        :param list_unused:  A boolean indicating whether to list the unused AWS entities or not.
        :return: An instance of the report which describes which resources need to be reconfigured (and how),
                                and which resources should be removed
        """
        account_id = self._get_account_id_from_profile()
        iam_data = self._get_data_from_aws(account_id, list_unused)

        return RuntimeReport(account_id, iam_data)

    def _get_data_from_aws(self, account_id: str, list_unused: bool) -> dict:
        """
        This method encapsulates all the API calls made to the AWS IAM service to gather data for later analysis
        :return: The IAM data that was pulled from the account, as was also saved locally for quicker re-runs
        """
        current_dir = os.path.abspath(os.path.dirname(__file__))
        iam_data_path = "{0}/{1}".format(current_dir, IAM_DATA_FILE_NAME)
        data_account_id = RuntimeIamScanner._get_account_id_from_existing_data(iam_data_path)
        if not self.refresh_cache and data_account_id == account_id:
            print("Reusing local data")
        else:
            print(f"Getting all IAM configurations for account {account_id}")
            iam = self._session.client('iam')
            iam.generate_credential_report()
            account_users, account_roles, account_groups, account_policies = RuntimeIamScanner.get_account_iam_configuration(iam)
            print("Getting IAM credential report")
            csv_credential_report = iam.get_credential_report()['Content'].decode('utf-8')
            credential_report = RuntimeIamScanner.convert_csv_to_json(csv_credential_report)

            if list_unused:
                account_principals = account_users + account_roles
                entity_arn_list = list(map(lambda e: e['Arn'], account_principals))
                last_accessed_map = self._generate_last_access(iam, entity_arn_list)

                for arn, last_accessed_list in last_accessed_map.items():
                    entity = next(entity for entity in account_principals if entity['Arn'] == arn)
                    entity['LastAccessed'] = last_accessed_list

            print("Collecting password configurations for all IAM users in the account")
            for user in account_users:
                try:
                    iam.get_login_profile(UserName=user['UserName'])
                    user['LoginProfileExists'] = True
                except ClientError as exception:
                    if exception.response['Error']['Code'] == 'NoSuchEntity':
                        user['LoginProfileExists'] = False
                    else:
                        raise exception

            print("Completed data collection, writing to local file...")
            iam_data = {
                'CredentialReport': credential_report,
                'AccountUsers': account_users,
                'AccountRoles': account_roles,
                'AccountGroups': account_groups,
                'AccountPolicies': account_policies
            }
            with open(iam_data_path, "w") as iam_file:
                json.dump(iam_data, iam_file, indent=4, sort_keys=True, default=str)
        with open(iam_data_path) as iam_data_file:
            iam_data = json.load(iam_data_file)

        return iam_data

    def _get_aws_iam_client(self):
        """
        Create an AWS IAM client with the profile that was supplies or default credentials if none was supplied
        :return: AWS IAM client
        """

    @staticmethod
    def get_account_iam_configuration(iam):
        marker = None
        paginator = iam.get_paginator('get_account_authorization_details')
        account_users = []
        account_roles = []
        account_policies = []
        account_groups = []
        response_iterator = paginator.paginate(
            Filter=['User', 'Role', 'Group', 'LocalManagedPolicy', 'AWSManagedPolicy'],
            PaginationConfig={
                'PageSize': 100,
                'StartingToken': marker
            }
        )
        for page in response_iterator:
            account_users.extend(page['UserDetailList'])
            account_roles.extend(page['RoleDetailList'])
            account_groups.extend(page['GroupDetailList'])
            account_policies.extend(page['Policies'])

        for policy in account_policies:
            policy['Description'] = iam.get_policy(PolicyArn=policy['Arn'])['Policy'].get('Description', '')

        marker = None
        list_roles_result = []
        paginator = iam.get_paginator('list_roles')
        response_iterator = paginator.paginate(
            PaginationConfig={
                'PageSize': 100,
                'StartingToken': marker
            }
        )
        for page in response_iterator:
            list_roles_result.extend(page['Roles'])

        for role in account_roles:
            role['Description'] = next(role_obj.get('Description', '') for role_obj in list_roles_result if role_obj['RoleName'] == role['RoleName'])

        account_policies = list(filter(lambda p: p['Arn'].split(':')[4] != '', account_policies))
        account_roles = list(filter(lambda r: r['Arn'].split('/')[1] != 'aws-service-role', account_roles))
        return account_users, account_roles, account_groups, account_policies

    def _generate_last_access(self, iam, arn_list: list):
        results = {}
        i = 1
        count = len(arn_list)
        for arn in arn_list:
            try:
                print(ERASE_LINE + f"\r{i} of {count}: Generating report for {arn}", end="")
                job_id = iam.generate_service_last_accessed_details(Arn=arn)['JobId']
                i += 1
            except ClientError as error:
                if error.response['Error']['Code'] == 'Throttling':
                    print('Reached throttling, sleeping for 5 seconds')
                    time.sleep(5)
                    job_id = iam.generate_service_last_accessed_details(Arn=arn)['JobId']
                else:
                    raise error
            results[arn] = job_id
        print(ERASE_LINE + "\rGenerated reports for all principals")

        i = 1
        for arn in results:
            job_id = results[arn]
            try:
                print(ERASE_LINE + f"\r{i} of {count}: Getting report for {arn}", end="")
                results[arn] = RuntimeIamScanner.simplify_service_access_result(
                    iam.get_service_last_accessed_details(JobId=job_id)['ServicesLastAccessed']
                )
                i += 1
            except ClientError as error:
                if error.response['Error']['Code'] == 'Throttling':
                    print('Reached throttling, sleeping for 5 seconds')
                    time.sleep(5)
                    results[arn] = RuntimeIamScanner.simplify_service_access_result(
                        iam.get_service_last_accessed_details(JobId=job_id)['ServicesLastAccessed']
                    )
                else:
                    raise error
        print(ERASE_LINE + "\rReceived usage results for all principals")
        return results

    @staticmethod
    def convert_csv_to_json(csv_report: str):
        """
        Convert a CSV string to a json file by parsing the first row as keys, and the rows as values
        :param csv_report: a csv string, delimited with "," and rows split with "\n"
        :return: The csv as a json array
        """
        json_report = []
        rows = csv_report.split('\n')
        headers = rows[0].split(',')
        for row in rows[1:]:
            values = row.split(',')
            entity = {}
            for i in range(len(values)):
                if values[i] != 'N/A':
                    entity[headers[i]] = values[i]
            json_report.append(entity)
        return json_report

    @staticmethod
    def simplify_service_access_result(service_access_list: list):
        """
        Simplifies AWS's service_last_accessed object by keeping only the relevant fields of the services that were in use
        :param service_access_list: List of service_last_accessed objects as received from the API
        :return: A list of objects of the format {"ServiceNamespace": ..., "LastAccessed": ...}, and only those that were in use
        """
        return list(map(lambda last_access: {"ServiceNamespace": last_access["ServiceNamespace"], "LastAccessed": last_access["LastAuthenticated"]},
                        filter(lambda last_access: last_access['TotalAuthenticatedEntities'] > 0, service_access_list)))

    def _get_account_id_from_profile(self):
        sts = self._session.client('sts')
        return sts.get_caller_identity()['Account']

    @staticmethod
    def _get_account_id_from_existing_data(path):
        # noinspection PyBroadException
        try:
            with open(path) as iam_data_file:
                iam_data = json.load(iam_data_file)
            return iam_data['AccountUsers'][0]['Arn'].split(":")[4]
        except Exception:
            return ""
