from airiam.runtime_iam_evaluator.BaseOrganizer import BaseOrganizer
from itertools import islice


ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
READ_ONLY_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'


class UserOrganizer(BaseOrganizer):
    def __init__(self, logger, unused_threshold=90):
        self.logger = logger
        self.unused_threshold = unused_threshold

    def get_user_clusters(self, iam_data):
        unused_users, human_users, service_users = self._separate_user_types(iam_data['AccountUsers'], iam_data['CredentialReport'])
        simple_user_clusters = self._create_simple_user_clusters(human_users, iam_data['AccountGroups'], iam_data['AccountPolicies'])
        return unused_users, human_users, service_users, simple_user_clusters

    def _create_simple_user_clusters(self, users, account_groups, account_policies):
        clusters = {"Admins": [], "ReadOnly": []}

        policies_in_use = {}
        for user in users:
            user_attached_managed_policies = []
            user_attached_managed_policies.extend(user['AttachedManagedPolicies'])
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
                    policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
                    policy_statements = UserOrganizer.convert_to_list(policy_document['Statement'])
                    actions_list = list(map(lambda statement: UserOrganizer.convert_to_list(statement['Action']), policy_statements))
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

                for pol in user_attached_managed_policies_in_use:
                    if pol not in policies_in_use:
                        policies_in_use[pol] = 0
                    policies_in_use[pol] += 1
                clusters['ReadOnly'].append(user["UserName"])
        policies_sorted = {k: v for k, v in sorted(policies_in_use.items(), key=lambda item: -item[1])}

        top_10_policies = list(islice(map(lambda item: item[0], policies_sorted.items()), 10))
        clusters["Powerusers"] = top_10_policies
        return clusters

    def _separate_user_types(self, account_users, credential_report):
        human_users = []
        service_users = []
        unused_users = []
        for user in account_users:
            credentials = next(creds for creds in credential_report if creds['user'] == user['UserName'])
            in_use = min(
                UserOrganizer.days_from_today(credentials.get('access_key_1_last_used_date', 'N/A')),
                UserOrganizer.days_from_today(credentials.get('access_key_2_last_used_date', 'N/A')),
                UserOrganizer.days_from_today(credentials.get('password_last_used', 'N/A')),
            ) < 90
            if not in_use:
                unused_users.append(user)
            if user['LoginProfileExists'] and UserOrganizer.days_from_today(credentials['password_last_used']) < self.unused_threshold:
                human_users.append(user)
            else:
                service_users.append(user)

        return unused_users, human_users, service_users

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
