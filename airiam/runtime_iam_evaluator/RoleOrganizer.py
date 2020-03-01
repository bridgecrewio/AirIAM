from .BaseOrganizer import BaseOrganizer


class RoleOrganizer(BaseOrganizer):
    def __init__(self, logger):
        self.logger = logger

    def rightsize_privileges(self, account_service_entities, account_policies, account_groups):
        unused_roles = []
        rightsized_roles = []
        for entity in account_service_entities:
            if len(entity['LastAccessed']) == 0:
                entity['LastUsed'] = 365
                unused_roles.append(entity)
            else:
                last_used = max(map(lambda last_access: last_access['LastAccessed'], entity.get('LastAccessed', [])))
                entity['LastUsed'] = BaseOrganizer.days_from_today(last_used)
                if entity['LastUsed'] <= 90:
                    rightsized_roles.append({
                        "Entity": entity,
                        # TODO: rightsize the policies
                        # "RightsizedPolicies": RoleOrganizer.rightsize_policies(entity, account_policies, account_groups)
                    })
                else:
                    unused_roles.append(entity)
        return unused_roles, rightsized_roles

    @staticmethod
    def rightsize_policies(entity, policies, groups):
        return {}
