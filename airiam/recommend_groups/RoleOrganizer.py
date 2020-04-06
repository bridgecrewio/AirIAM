class RoleOrganizer:
    def __init__(self, logger, unused_threshold):
        super().__init__()
        self._unused_threshold = unused_threshold
        self.logger = logger

    @staticmethod
    def rightsize_privileges(iam_data: dict):
        roles = iam_data['AccountRoles']
        unused_roles = []
        rightsized_roles = []
        for role in roles:
            rightsized_roles.append({"role": role, "policies_to_detach": []})
        return unused_roles, rightsized_roles
