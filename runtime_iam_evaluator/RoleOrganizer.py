from .BaseOrganizer import BaseOrganizer


class RoleOrganizer(BaseOrganizer):
    def __init__(self, logger, unused_threshold):
        super().__init__()
        self._unused_threshold = unused_threshold
        self.logger = logger

    def rightsize_privileges(self, iam_data: dict):
        roles = iam_data['AccountRoles']
        account_policies = iam_data['AccountPolicies']
        unused_roles = []
        rightsized_roles = []
        for role in roles:
            if len(role['LastAccessed']) == 0:
                role['LastUsed'] = 365
                unused_roles.append(role)
            else:
                last_used = max(map(lambda last_access: last_access['LastAccessed'], role.get('LastAccessed', [])))
                role['LastUsed'] = BaseOrganizer.days_from_today(last_used)
                if role['LastUsed'] <= self._unused_threshold:
                    policies_to_detach = self.find_unused_attached_policies(role, account_policies)
                    rightsized_roles.append({"role": role, "policies_to_detach": policies_to_detach})
                else:
                    unused_roles.append(role)
        return unused_roles, rightsized_roles

    @staticmethod
    def find_unused_attached_policies(role: dict, account_policies: list) -> list:
        unused_policy_attachments = []
        services_last_accessed = list(map(lambda access_obj: access_obj['ServiceNamespace'], role['LastAccessed']))
        for managed_policy in role['AttachedManagedPolicies']:
            policy_obj = next(pol for pol in account_policies if pol['Arn'] == managed_policy['PolicyArn'])
            policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
            if BaseOrganizer.is_policy_unused(policy_document, services_last_accessed):
                unused_policy_attachments.append({"Role": role['RoleName'], "Policy": managed_policy['PolicyArn']})

        for inline_policy in role.get('RolePolicyList', []):
            if BaseOrganizer.is_policy_unused(inline_policy['PolicyDocument'], services_last_accessed):
                unused_policy_attachments.append({"Role": role['RoleName'], "Policy": inline_policy['PolicyName']})
        return unused_policy_attachments
