import datetime as dt
import json
import os

import boto3
from botocore.exceptions import ClientError

IAM_DATA_FILE_NAME = "iam_data.json"


class RuntimeIamEvaluator:
    def __init__(self, logger, profile=None, unused_threshold=90):
        self.unused_threshold = unused_threshold
        self.logger = logger
        self.profile = profile

    def evaluate_runtime_iam(self, should_refresh):
        iam_data = self.get_iam_data(should_refresh)

        user_clusters = self.create_user_clusters(iam_data['AccountUsers'], iam_data['AccountGroups'], iam_data['AccountPolicies'])

        cluster_csv_str = "Users,Policies Attached\n" + "\n".join(
            list(map(lambda cluster_id: "\"{}\",\"{}\"".format(user_clusters[cluster_id], cluster_id), user_clusters))
        )
        with open("user_clusters.csv", "w") as user_clusters_file:
            user_clusters_file.write(cluster_csv_str)
        return user_clusters

    def get_iam_data(self, should_refresh):
        if should_refresh or not os.path.exists(IAM_DATA_FILE_NAME):
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

        else:
            self.logger.info("Reusing local data")

        with open(IAM_DATA_FILE_NAME) as iam_data_file:
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
            for i in range(22):
                if values[i] != 'N/A':
                    entity[headers[i]] = values[i]
            json_report.append(entity)
        return json_report

    def create_user_clusters(self, account_users, account_groups, account_policies):
        clusters = {}
        for user in account_users:
            user_attached_managed_policies = []
            user_attached_managed_policies.extend(user['AttachedManagedPolicies'])
            for group_name in user['GroupList']:
                group_managed_policies = next(g['AttachedManagedPolicies'] for g in account_groups if g['GroupName'] == group_name)
                user_attached_managed_policies.extend(group_managed_policies)
            user_attached_managed_policies = list(set(map(lambda p: p['PolicyArn'], user_attached_managed_policies)))
            user_attached_managed_policies.sort()

            services_in_use = list(
                map(
                    lambda last_access: last_access['ServiceNamespace'],
                    filter(
                        lambda last_access: RuntimeIamEvaluator.days_from_today(last_access['LastAccessed']) < self.unused_threshold,
                        user['LastAccessed']
                    )
                )
            )

            user_attached_managed_policies_in_use = []
            for policy_arn in user_attached_managed_policies:
                services_allowed = []
                policy_obj = next(p for p in account_policies if policy_arn == p['Arn'])
                policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
                policy_statements = RuntimeIamEvaluator.convert_to_list(policy_document['Statement'])
                actions_list = list(map(lambda statement: RuntimeIamEvaluator.convert_to_list(statement['Action']), policy_statements))
                for actions in actions_list:
                    services_allowed = list(set(services_allowed + list(map(lambda action: action.split(":")[0], actions))))
                policy_in_use = False
                for service in services_allowed:
                    if service in services_in_use or service == "*":
                        policy_in_use = True
                        break
                if policy_in_use:
                    user_attached_managed_policies_in_use.append(policy_arn)

            if user['LoginProfileExists'] and 'arn:aws:iam::aws:policy/IAMUserChangePassword' not in user_attached_managed_policies_in_use:
                user_attached_managed_policies_in_use.append('arn:aws:iam::aws:policy/IAMUserChangePassword')

            user_policies_str = ", ".join(user_attached_managed_policies_in_use)
            if user_policies_str in clusters:
                clusters[user_policies_str].append(user['UserName'])
            else:
                clusters[user_policies_str] = [user['UserName']]
        for cluster_id, cluster_users in clusters.items():
            clusters[cluster_id] = ", ".join(cluster_users)

        return clusters

    @staticmethod
    def convert_to_list(list_or_single_object):
        if isinstance(list_or_single_object, list):
            return list_or_single_object
        return [list_or_single_object]

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

    @staticmethod
    def days_from_today(str_date_from_today):
        date = dt.datetime.fromisoformat(str_date_from_today).replace(tzinfo=None)
        delta = dt.datetime.now() - date

        return delta.days
