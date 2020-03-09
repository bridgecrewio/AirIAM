SORT_KEY_BY_ENTITY_TYPE = {
    'AccountGroups': 'GroupName',
    'AccountPolicies': 'PolicyName',
    'AccountRoles': 'RoleName',
    'AccountUsers': 'UserName'
}


class RuntimeReport:
    def __init__(self, account_id, raw_results, unused_users, unused_roles, unattached_policies, redundant_groups, user_reorg, role_reorg):
        self.account_id = account_id
        self._raw_results = raw_results
        self._unused_users = unused_users
        self._unused_roles = unused_roles
        self._unattached_policies = unattached_policies
        self._redundant_groups = redundant_groups
        self._user_reorg = user_reorg
        self._role_reorg = role_reorg

        self._sort_findings()

    def get_raw_data(self) -> dict:
        return self._raw_results

    def get_unused(self) -> dict:
        return {
            "Users": self._unused_users,
            "Roles": self._unused_roles,
            "Policies": self._unattached_policies,
            "Groups": self._redundant_groups
        }

    def get_rightsizing(self) -> dict:
        return {
            "Users": self._user_reorg,
            "Roles": self._role_reorg,
        }

    def _sort_findings(self) -> None:
        for entity_type, lst in self._raw_results.items():
            if entity_type == 'CredentialReport':
                continue
            lst.sort(key=lambda e: SORT_KEY_BY_ENTITY_TYPE[entity_type])

        self._unused_users.sort(key=lambda user: SORT_KEY_BY_ENTITY_TYPE['AccountUsers'])
        self._unused_roles.sort(key=lambda role: SORT_KEY_BY_ENTITY_TYPE['AccountRoles'])
        self._redundant_groups.sort(key=lambda group: SORT_KEY_BY_ENTITY_TYPE['AccountGroups'])
        self._unattached_policies.sort(key=lambda policy: SORT_KEY_BY_ENTITY_TYPE['AccountPolicies'])

        self._role_reorg.sort(key=lambda role: role['Entity'][SORT_KEY_BY_ENTITY_TYPE['AccountRoles']])
        self._user_reorg['Admins'].sort()
        self._user_reorg['ReadOnly'].sort()
        self._user_reorg['Powerusers']['Users'].sort()
