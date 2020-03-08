SORT_KEY_BY_ENTITY_TYPE = {
    'AccountGroups': 'GroupName',
    'AccountPolicies': 'PolicyName',
'AccountRoles': 'RoleName',
    'AccountUsers': 'UserName'
}


class RuntimeReport:
    def __init__(self, account_id, raw_results, unused_users, unused_roles, unattached_policies, redundant_groups, user_reorg, role_reorg):
        self.account_id = account_id
        self.raw_results = raw_results
        self.unused_users = unused_users
        self.unused_roles = unused_roles
        self.unattached_policies = unattached_policies
        self.redundant_groups = redundant_groups
        self.user_reorg = user_reorg
        self.role_reorg = role_reorg

        self.sort_findings()

    def get_raw_data(self) -> dict:
        return self.raw_results

    def get_unused(self) -> dict:
        return {
            "Users": self.unused_users,
            "Roles": self.unused_roles,
            "Policies": self.unattached_policies,
            "Groups": self.redundant_groups
        }

    def get_rightsizing(self) -> dict:
        return {
            "Users": self.user_reorg,
            "Roles": self.role_reorg,
        }

    def sort_findings(self) -> None:
        for entity_type, lst in self.raw_results.items():
            if entity_type == 'CredentialReport':
                continue
            lst.sort(key=lambda e: SORT_KEY_BY_ENTITY_TYPE[entity_type])

        self.unused_users.sort(key=lambda user: SORT_KEY_BY_ENTITY_TYPE['AccountUsers'])
        self.unused_roles.sort(key=lambda role: SORT_KEY_BY_ENTITY_TYPE['AccountRoles'])
        self.redundant_groups.sort(key=lambda group: SORT_KEY_BY_ENTITY_TYPE['AccountGroups'])
        self.unattached_policies.sort(key=lambda policy: SORT_KEY_BY_ENTITY_TYPE['AccountPolicies'])

        self.role_reorg.sort(key=lambda role: role['Entity'][SORT_KEY_BY_ENTITY_TYPE['AccountRoles']])
        self.user_reorg['Admins'].sort()
        self.user_reorg['ReadOnly'].sort()
        self.user_reorg['Powerusers']['Users'].sort()
