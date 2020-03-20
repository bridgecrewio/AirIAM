import os
import ssl
import re
import copy

import pandas as pd

from airiam.runtime_iam_evaluator.BaseOrganizer import BaseOrganizer

action_table_url = 'https://raw.githubusercontent.com/salesforce/policy_sentry/master/policy_sentry/shared/data/action_table.csv'

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context

ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
READ_ONLY_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'


class UserOrganizer(BaseOrganizer):
    def __init__(self, logger, unused_threshold=90):
        self.logger = logger
        self.unused_threshold = unused_threshold
        action_table = pd.read_csv(action_table_url, delimiter=";").to_dict('records')
        self.action_map = {}
        for action_obj in action_table:
            if action_obj['service'] not in self.action_map:
                self.action_map[action_obj['service']] = []
            self.action_map[action_obj['service']].append(action_obj)

    def get_user_clusters(self, iam_data):
        unused_users, human_users, unchanged_users = self._separate_user_types(iam_data['AccountUsers'], iam_data['CredentialReport'])
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
                            lambda last_access: UserOrganizer.days_from_today(last_access['LastAccessed']) < self.unused_threshold,
                            user['LastAccessed']
                        )
                    )
                )

                user_attached_managed_policies_in_use = []
                for policy_arn in user_attached_managed_policies:
                    services_allowed = []
                    policy_obj = next(p for p in account_policies if policy_arn == p['Arn'])
                    actions_list = self._get_policy_actions(policy_obj)
                    for actions in actions_list:
                        services_allowed = list(set(services_allowed + list(map(lambda action: action.split(":")[0], actions))))
                    policy_in_use = False
                    for service in services_allowed:
                        if service in services_in_use or service == "*":
                            policy_in_use = True
                            break
                    if policy_in_use:
                        user_attached_managed_policies_in_use.append(policy_arn)

                user_needs_write_access = False
                for pol in user_attached_managed_policies_in_use:
                    if pol not in policies_in_use:
                        policies_in_use[pol] = 0
                    policies_in_use[pol] += 1
                    policy_obj = next(p for p in account_policies if p['Arn'] == pol)
                    if self._policy_is_write_access(policy_obj):
                        user_needs_write_access = True

                if user_needs_write_access:
                    clusters['Powerusers']['Users'].append(user["UserName"])
                else:
                    clusters['ReadOnly'].append(user["UserName"])
        policies_sorted = list({k: v for k, v in sorted(policies_in_use.items(), key=lambda item: -item[1])}.keys())

        clusters["Powerusers"]["Policies"] = policies_sorted
        return clusters

    @staticmethod
    def _get_policy_actions(policy_obj):
        policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
        policy_statements = UserOrganizer.convert_to_list(policy_document['Statement'])
        actions_list = []
        for statement in policy_statements:
            if statement['Effect'] == 'Allow':
                actions_list.extend(UserOrganizer.convert_to_list(statement['Action']))
        return actions_list

    @staticmethod
    def _separate_user_types(account_users, credential_report):
        human_users = []
        unused_users = []
        unchanged_users = []
        for user in account_users:
            credentials = next(creds for creds in credential_report if creds['user'] == user['UserName'])
            last_used_in_days = min(
                UserOrganizer.days_from_today(credentials.get('access_key_1_last_used_date', 'N/A')),
                UserOrganizer.days_from_today(credentials.get('access_key_2_last_used_date', 'N/A')),
                UserOrganizer.days_from_today(credentials.get('password_last_used', 'N/A')),
            )
            if last_used_in_days >= 90:
                user['LastUsed'] = last_used_in_days
                unused_users.append(user)
            else:
                if len(user['AttachedManagedPolicies']) == 0 and len(user['GroupList']) == 0:
                    unchanged_users.append(user)
                else:
                    human_users.append(user)

        return unused_users, human_users, unchanged_users

    def _consolidate_user_clusters(self, simple_user_clusters):
        admin_cluster = simple_user_clusters.pop(ADMIN_POLICY_ARN)
        start_number_of_clusters = 0
        end_number_of_clusters = len(simple_user_clusters.keys())
        final_clusters = None
        while end_number_of_clusters != start_number_of_clusters:
            clusters = {}
            start_number_of_clusters = end_number_of_clusters
            for policies, users in simple_user_clusters.items():
                merged = False
                cluster_policies = policies.split(", ")
                for policies in clusters.keys():
                    iterator_cluster_policies = policies.split(", ")
                    merged_policies, num_of_changes = UserOrganizer.unify_lists(cluster_policies, iterator_cluster_policies)
                    if num_of_changes == 1:
                        self.logger.info("merge!")
                        merged = True
                if not merged:
                    clusters[", ".join(cluster_policies)] = users
            end_number_of_clusters = len(clusters.keys())
            final_clusters = clusters
        final_clusters[ADMIN_POLICY_ARN] = admin_cluster
        return final_clusters

    @staticmethod
    def unify_lists(l1, l2):
        merged = list(set(l1 + l2))
        merged.sort()
        return merged, max(len(merged) - len(l1), len(merged) - len(l2))

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

    def _policy_is_write_access(self, pol):
        actions = UserOrganizer._get_policy_actions(pol)
        for action in actions:
            if action == '*' or '*' in action.split(':'):
                return True
            [action_service, action_name] = action.split(':')
            if '*' in action_name:
                action_regex = action_name.replace('*', '.*')
                action_objs = list(filter(lambda action_obj: re.match(action_regex, action_obj['name']), self.action_map[action_service]))
            else:
                try:
                    action_objs = [next(action_obj for action_obj in self.action_map[action_service] if action_obj['name'] == action_name)]
                except StopIteration as e:
                    self.logger.error('Did not find action {}:{}'.format(action_service, action_name))
                    action_objs = []

            for action_obj in action_objs:
                if action_obj['access_level'] in ['Write', 'Delete', 'Permissions management']:
                    return True
        return False
