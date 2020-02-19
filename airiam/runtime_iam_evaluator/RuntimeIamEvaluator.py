import json
import os

import boto3
from botocore.exceptions import ClientError

IAM_DATA_FILE_NAME = "iam_data.json"


class RuntimeIamEvaluator:
    def __init__(self, logger, profile=None):
        self.logger = logger
        self.profile = profile

    def evaluate_runtime_iam(self, should_refresh):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        if not should_refresh and os.path.exists("{0}/{1}".format(current_dir, IAM_DATA_FILE_NAME)):
            self.logger.info("Reusing local data")
        else:
            iam = self.get_aws_iam_client()
            iam.generate_credential_report()
            self.logger.info("Getting all IAM configurations in the account")
            account_users, account_roles, account_groups, account_policies = RuntimeIamEvaluator.get_account_iam_configuration(iam)
            self.logger.info("Getting IAM credential report")
            csv_credential_report = iam.get_credential_report()['Content'].decode('utf-8')
            credential_report = RuntimeIamEvaluator.convert_csv_to_json(csv_credential_report)

            entity_arn_list = list(map(lambda e: e['Arn'], account_users + account_roles))
            self.logger.info("Getting service last accessed report for every user & role in the account")
            last_accessed_map = self.generate_last_access(iam, entity_arn_list)

            for arn, last_accessed_list in last_accessed_map.items():
                entity = next(entity for entity in account_users + account_roles if entity['Arn'] == arn)
                entity['LastAccessed'] = last_accessed_list

            self.logger.info("Collecting password configurations for all users in the account")
            for user in account_users:
                try:
                    iam.get_login_profile(UserName=user['UserName'])
                    user['LoginProfileExists'] = True
                except ClientError as exception:
                    if exception.response['Error']['Code'] == 'NoSuchEntity':
                        user['LoginProfileExists'] = False
                    else:
                        raise exception

            self.logger.info("Completed data collection, writing to local file...")
            iam_data = {
                'CredentialReport': credential_report,
                'AccountUsers': account_users,
                'AccountRoles': account_roles,
                'AccountGroups': account_groups,
                'AccountPolicies': account_policies
            }
            with open(IAM_DATA_FILE_NAME, "w") as iam_file:
                json.dump(json.dumps(iam_data, indent=4, sort_keys=True, default=str), iam_file)

        with open("{0}/{1}".format(current_dir, IAM_DATA_FILE_NAME)) as iam_data_file:
            iam_data = json.loads(json.load(iam_data_file))

        account_id = iam_data['AccountUsers'][0]['Arn'].split(":")[4]

        self.logger.info("Analyzing data for account {}".format(account_id))

        return iam_data

    def get_aws_iam_client(self):
        if self.profile:
            session = boto3.Session(profile_name=self.profile)
        else:
            session = boto3.Session()
        caller_identity = session.client('sts').get_caller_identity()
        scanned_account = caller_identity['Account']
        self.logger.info("Scanning account {}".format(scanned_account))
        return session.client('iam')

    @staticmethod
    def get_account_iam_configuration(iam):
        paginator = iam.get_paginator('get_account_authorization_details')
        account_users = []
        account_roles = []
        account_policies = []
        account_groups = []
        response_iterator = paginator.paginate(
            Filter=['User', 'Role', 'Group', 'LocalManagedPolicy', 'AWSManagedPolicy'],
            PaginationConfig={
                'MaxItems': 100,
                'StartingToken': None
            }
        )
        for page in response_iterator:
            account_users.extend(page['UserDetailList'])
            account_roles.extend(page['RoleDetailList'])
            account_groups.extend(page['GroupDetailList'])
            account_policies.extend(page['Policies'])

        account_policies = list(filter(lambda policy: policy['Arn'].split(':')[4] != '', account_policies))
        account_roles = list(filter(lambda role: role['Arn'].split('/')[1] != 'aws-service-role', account_roles))
        return account_users, account_roles, account_groups, account_policies

    @staticmethod
    def convert_csv_to_json(csv_report):
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

    def generate_last_access(self, iam, arn_list):
        results = {}
        for arn in arn_list:
            job_id = iam.generate_service_last_accessed_details(Arn=arn)['JobId']
            results[arn] = job_id

        for arn in results:
            job_id = results[arn]
            results[arn] = RuntimeIamEvaluator.simplify_service_access_result(
                iam.get_service_last_accessed_details(JobId=job_id)['ServicesLastAccessed']
            )
        self.logger.info(results)
        return results

    @staticmethod
    def simplify_service_access_result(service_access_list):
        return list(map(lambda last_access: {"ServiceNamespace": last_access["ServiceNamespace"], "LastAccessed": last_access["LastAuthenticated"]},
                        filter(lambda last_access: last_access['TotalAuthenticatedEntities'] > 0, service_access_list)))
