import copy
import json
import os

import boto3
from botocore.exceptions import ClientError

from airiam.runtime_iam_evaluator.RoleOrganizer import RoleOrganizer
from airiam.runtime_iam_evaluator.UserOrganizer import UserOrganizer
from airiam.models.RuntimeReport import RuntimeReport

IAM_DATA_FILE_NAME = "iam_data.json"


class RuntimeIamEvaluator:
    """
    This class encapsulates all Runtime IAM data capture & classification
    It's entry point is the method `evaluate_runtime_iam`
    """

    def __init__(self, logger, profile=None):
        self.logger = logger
        self.profile = profile

    def evaluate_runtime_iam(self, should_refresh: bool, unused_threshold=90):
        """
        This method encapsulates all Runtime IAM data capture & classification
        :param unused_threshold: The threshold, in days, for IAM entities to be considered unused. Default is 90
        :param should_refresh:  A boolean indicating whether to get data from AWS APIs or use local data (if exists).
                                Calling the AWS APIs may take a few minutes
        :return: An instance of the report which describes which resources need to be reconfigured (and how),
                                and which resources should be removed
        :rtype: RuntimeReport
        """
        iam_data = self._get_data_from_aws(should_refresh)

        account_id = iam_data['AccountUsers'][0]['Arn'].split(":")[4]
        self.logger.info("Analyzing data for account {}".format(account_id))

        unused_users, human_users, simple_user_clusters, entities_to_detach, unchanged_users = \
            UserOrganizer(self.logger, unused_threshold).get_user_clusters(iam_data)
        unused_roles, role_rightsizing = RoleOrganizer(self.logger).rightsize_privileges(iam_data['AccountRoles'], iam_data['AccountPolicies'],
                                                                                         iam_data['AccountGroups'])

        groups_with_no_active_members = self._find_groups_with_no_members(iam_data['AccountGroups'], human_users)
        groups_with_no_privilege = list(filter(lambda g: len(g['AttachedManagedPolicies'] + g['GroupPolicyList']) == 0, iam_data['AccountGroups']))
        redundant_groups = groups_with_no_active_members + groups_with_no_privilege

        unattached_policies = list(filter(lambda policy: policy['AttachmentCount'] > 0, iam_data['AccountPolicies']))
        return RuntimeReport(account_id, unused_users, unused_roles, unattached_policies,  redundant_groups, simple_user_clusters, unchanged_users,
                             role_rightsizing)

    def _get_data_from_aws(self, should_refresh: bool):
        """
        This method encapsulates all the API calls made to the AWS IAM service to gather data for later analysis
        :param should_refresh:  A boolean indicating whether to get data from AWS APIs or use local data (if exists).
                                Calling the AWS APIs may take a few minutes
        :return: The IAM data that was pulled from the account, as was also saved locally for quicker re-runs
        """
        current_dir = os.path.abspath(os.path.dirname(__file__))
        iam_data_path = "{0}/{1}".format(current_dir, IAM_DATA_FILE_NAME)
        if not should_refresh and os.path.exists(iam_data_path):
            self.logger.info("Reusing local data")
        else:
            iam = self._get_aws_iam_client()
            iam.generate_credential_report()
            self.logger.info("Getting all IAM configurations in the account")
            account_users, account_roles, account_groups, account_policies = RuntimeIamEvaluator.get_account_iam_configuration(iam)
            self.logger.info("Getting IAM credential report")
            csv_credential_report = iam.get_credential_report()['Content'].decode('utf-8')
            credential_report = RuntimeIamEvaluator.convert_csv_to_json(csv_credential_report)

            entity_arn_list = list(map(lambda e: e['Arn'], account_users + account_roles))
            self.logger.info("Getting service last accessed report for every user & role in the account")
            last_accessed_map = self._generate_last_access(iam, entity_arn_list)

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
            with open(iam_data_path, "w") as iam_file:
                json.dump(json.dumps(iam_data, indent=4, sort_keys=True, default=str), iam_file)
        with open(iam_data_path) as iam_data_file:
            iam_data = json.loads(json.load(iam_data_file))

        return iam_data

    def _get_aws_iam_client(self):
        """
        Create an AWS IAM client with the profile that was supplies or default credentials if none was supplied
        :return: AWS IAM client
        """
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

    def _generate_last_access(self, iam, arn_list: list):
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

    def _find_groups_with_no_members(self, group_list: list, user_list: list):
        """
        Identify groups with no members by going through the
        :param group_list: List of the groups in the account
        :param user_list:  List of the active IAM users in the account
        :return: List of groups which have no active IAM users as members
        """
        empty_groups = copy.deepcopy(group_list)
        for user in user_list:
            for group in user['GroupList']:
                try:
                    group_obj = next(g for g in empty_groups if g['GroupName'] == group)
                    empty_groups.remove(group_obj)
                except StopIteration:
                    self.logger.debug('Duplicate usage of group {}'.format(group))

        return empty_groups
