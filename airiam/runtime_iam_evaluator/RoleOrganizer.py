class RoleOrganizer:
    def __init__(self, logger):
        self.logger = logger

    def rightsize_privileges(self, account_service_entities):
        unused_roles = []
        for entity in account_service_entities:
            if entity.get('LastAccessed', None) and entity['LastAccessed']:
                self.logger.info(entity)
                # todo: compute unused roles and how we can rightsize existing roles.
        return unused_roles, []
