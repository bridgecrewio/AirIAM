class RuntimeReport:
    def __init__(self, account_id, unused_users, unused_roles, unattached_policies, redundant_groups, user_clusters, special_users, role_rightsizing):
        self.account_id = account_id
        self.unused_users = unused_users
        self.unused_roles = unused_roles
        self.unattached_policies = unattached_policies
        self.redundant_groups = redundant_groups
        self.user_clusters = user_clusters
        self.special_users = special_users
        self.role_rightsizing = role_rightsizing
