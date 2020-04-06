import copy
import os
import ssl

from airiam.find_unused.find_unused import days_from_today
from airiam.models.RuntimeReport import RuntimeReport
from airiam.find_unused.PolicyAnalyzer import PolicyAnalyzer

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    # noinspection PyProtectedMember
    ssl._create_default_https_context = ssl._create_unverified_context

ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
READ_ONLY_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'


def recommend_groups(logger, runtime_iam_report: RuntimeReport, unused_threshold=90):
    account_id = runtime_iam_report.get_raw_data()['AccountRoles'][0]['Arn'].split(":")[4]
    logger.info("Analyzing data for account {}".format(account_id))

    runtime_iam_report.set_reorg(UserOrganizer(logger, unused_threshold).get_user_clusters(runtime_iam_report))

    return runtime_iam_report


class UserOrganizer:
    def __init__(self, logger, unused_threshold=90):
        super().__init__()
        self.logger = logger
        self.unused_threshold = unused_threshold

    def get_user_clusters(self, runtime_report: RuntimeReport):
        iam_data = runtime_report.get_raw_data()
        unused_users, human_users, unchanged_users = self._separate_user_types(iam_data['AccountUsers'])
        simple_user_clusters = self._create_simple_user_clusters(human_users, iam_data['AccountGroups'], iam_data['AccountPolicies'])
        simple_user_clusters['UnchangedUsers'] = unchanged_users
        entities_to_detach = UserOrganizer.calculate_detachments(human_users)
        return unused_users, human_users, simple_user_clusters, entities_to_detach

    def _create_simple_user_clusters(self, users, account_groups, account_policies):
        clusters = {"Admins": [], "ReadOnly": [], "Powerusers": {'Users': [], 'Policies': []}}

        policies_in_use = {}
        for user in users:
            user_attached_managed_policies = copy.deepcopy(user['AttachedManagedPolicies'])
            for group_name in user['GroupList']:
                group_managed_policies = next(g['AttachedManagedPolicies'] for g in account_groups if g['GroupName'] == group_name)
                user_attached_managed_policies.extend(group_managed_policies)
            user_attached_managed_policies = list(set(map(lambda p: p['PolicyArn'], user_attached_managed_policies)))
            user_attached_managed_policies.sort()
            if ADMIN_POLICY_ARN in user_attached_managed_policies:
                clusters["Admins"].append(user['UserName'])
            else:
                services_in_use = list(
                    map(
                        lambda last_access: last_access['ServiceNamespace'],
                        filter(
                            lambda last_access: days_from_today(last_access['LastAccessed']) < self.unused_threshold,
                            user['LastAccessed']
                        )
                    )
                )

                user_attached_managed_policies_in_use = []
                for policy_arn in user_attached_managed_policies:
                    policy_obj = next(p for p in account_policies if policy_arn == p['Arn'])
                    policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
                    policy_in_use = not PolicyAnalyzer.is_policy_unused(policy_document, services_in_use)
                    if policy_in_use:
                        user_attached_managed_policies_in_use.append(policy_arn)

                user_needs_write_access = False
                for pol in user_attached_managed_policies_in_use:
                    if pol not in policies_in_use:
                        policies_in_use[pol] = 0
                    policies_in_use[pol] += 1
                    policy_obj = next(p for p in account_policies if p['Arn'] == pol)
                    policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
                    if PolicyAnalyzer.policy_is_write_access(policy_document):
                        user_needs_write_access = True
                        break

                if user_needs_write_access:
                    clusters['Powerusers']['Users'].append(user["UserName"])
                else:
                    clusters['ReadOnly'].append(user["UserName"])
        policies_sorted = list({k: v for k, v in sorted(policies_in_use.items(), key=lambda item: -item[1])}.keys())

        clusters["Powerusers"]["Policies"] = policies_sorted
        return clusters

    def _separate_user_types(self, account_users):
        human_users = []
        unused_users = []
        unchanged_users = []
        for user in account_users:
            if user['LastUsed'] >= self.unused_threshold:
                unused_users.append(user)
            else:
                if len(user['AttachedManagedPolicies']) == 0 and len(user['GroupList']) == 0:
                    unchanged_users.append(user)
                else:
                    human_users.append(user)

        return unused_users, human_users, unchanged_users

    @staticmethod
    def calculate_detachments(human_users):
        detachments = []
        for user in human_users:
            for entity in user.get('GroupList', []):
                detachments.append({
                    'UserName': user['UserName'],
                    'EntityType': 'Group',
                    'EntityId': entity
                })
            for entity in list(map(lambda u: u['PolicyName'], user.get('UserPolicyList', []))):
                detachments.append({
                    'UserName': user['UserName'],
                    'EntityType': 'UserPolicy',
                    'EntityId': entity
                })
            for entity in user.get('AttachedManagedPolicies', []):
                detachments.append({
                    'UserName': user['UserName'],
                    'EntityType': 'AttachedManagedPolicy',
                    'EntityId': entity
                })

        return detachments
