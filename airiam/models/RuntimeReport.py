SORT_KEY_BY_ENTITY_TYPE = {
    'AccountGroups': 'GroupName',
    'AccountPolicies': 'Arn',
    'AccountRoles': 'RoleName',
    'AccountUsers': 'UserName'
}


class RuntimeReport:
    def __init__(self, account_id: str, identity_arn: str, raw_results: dict):
        self.account_id = account_id
        self.identity_arn = identity_arn
        self._raw_results = raw_results
        self._unused_users = None
        self._unused_roles = None
        self._unattached_policies = None
        self._redundant_groups = None
        self._unused_active_access_keys = None
        self._unused_console_login_profiles = None
        self._unused_policy_attachments = None
        self._user_group_recommendation = None

    def get_raw_data(self) -> dict:
        return self._raw_results

    def get_unused(self) -> dict:
        return {
            'Users': self._unused_users,
            'UnusedActiveAccessKeys': self._unused_active_access_keys,
            'UnusedConsoleLoginProfiles': self._unused_console_login_profiles,
            'Roles': self._unused_roles,
            'Policies': self._unattached_policies,
            'Groups': self._redundant_groups,
            'PolicyAttachments': self._unused_policy_attachments
        }

    def get_user_groups(self) -> dict:
        return self._user_group_recommendation

    def set_unused(self, unused_users, unused_roles, unused_active_access_keys, unused_console_login_profiles, unattached_policies, redundant_groups,
                   unused_policy_attachments):
        self._unused_users = sorted(unused_users, key=lambda user: SORT_KEY_BY_ENTITY_TYPE['AccountUsers'])
        self._unused_roles = sorted(unused_roles, key=lambda role: SORT_KEY_BY_ENTITY_TYPE['AccountRoles'])
        self._unused_active_access_keys = sorted(unused_active_access_keys, key=lambda access_key: access_key['User'])
        self._unused_console_login_profiles = sorted(unused_console_login_profiles, key=lambda access_key: access_key['User'])
        self._unattached_policies = sorted(unattached_policies, key=lambda policy: SORT_KEY_BY_ENTITY_TYPE['AccountPolicies'])
        self._redundant_groups = sorted(redundant_groups, key=lambda group: SORT_KEY_BY_ENTITY_TYPE['AccountGroups'])
        self._unused_policy_attachments = sorted(unused_policy_attachments, key=RuntimeReport.policy_attachment_sorter)

    @staticmethod
    def policy_attachment_sorter(policy_attachment):
        return policy_attachment.get('Role') or policy_attachment.get('User') or policy_attachment.get('Group')

    def set_reorg(self, user_group_recommendation):
        self._user_group_recommendation = user_group_recommendation
