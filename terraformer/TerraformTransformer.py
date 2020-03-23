from python_terraform import *

from models.RuntimeReport import RuntimeReport
from terraformer.entity_terraformers.AWSProviderTransformer import AWSProviderTransformer
from terraformer.entity_terraformers.IAMGroupTransformer import IAMGroupTransformer
from terraformer.entity_terraformers.IAMPolicyTransformer import IAMPolicyTransformer
from terraformer.entity_terraformers.IAMRoleTransformer import IAMRoleTransformer
from terraformer.entity_terraformers.IAMUserGroupMembershipTransformer import IAMUserGroupMembershipTransformer
from terraformer.entity_terraformers.IAMUserTransformer import IAMUserTransformer

current_dir = os.path.abspath(os.path.dirname(__file__))
boilerplate_files = ["admins.tf", "developers.tf", "power_users.tf"]
ERASE_LINE = '\x1b[2K'


class TerraformTransformer:
    def __init__(self, logger, profile=None, result_dir='results'):
        self.logger = logger
        self.profile = profile
        self._result_dir = result_dir
        if not os.path.exists(self._result_dir):
            os.mkdir(self._result_dir)

    def transform(self, rightsize: bool, results: RuntimeReport, should_import=True) -> str:
        try:
            entities_to_import = self._create_current_state(results.get_raw_data())

            tf = Terraform(working_dir=self._result_dir)
            tf.init(backend=False)
            if should_import:
                num_of_entities_to_import = len(entities_to_import)
                print(f"Importing {num_of_entities_to_import} entities")
                i = 1
                for entity_to_import in entities_to_import:
                    msg = f"#{i} of {num_of_entities_to_import}: Importing {entity_to_import['entity']} to {entity_to_import['identifier']}"
                    print(ERASE_LINE + f"\r{msg}", end="")
                    return_code, stdout, stderr = tf.import_cmd(entity_to_import['identifier'], entity_to_import['entity'])
                    if return_code != 0 and 'Resource already managed by Terraform' not in stderr:
                        self.logger.error(f"Error: {stderr}")
                    i += 1
                print("Imported all existing entities to state")

            if rightsize:
                self._create_rightsized_state(results.get_rightsizing())
            tf.fmt()
            return "Success"
        except Exception as e:
            self.logger.error(e)
            raise e

    def _create_current_state(self, iam_raw_data: dict) -> list:
        entities_to_import = []
        with open(f"{self._result_dir}/main.tf", 'w') as main_file:
            main_code = AWSProviderTransformer({'region': 'us-east-1', 'profile': self.profile}).code()
            main_file.write(main_code)

        policies_identifiers = {}

        with open(f"{self._result_dir}/policies.tf", 'w') as policies_file:
            policy_code = ""
            for policy in iam_raw_data['AccountPolicies']:
                if 'iam::aws:' in policy['Arn']:
                    # Don't create AWS managed policies
                    continue
                policy_transformer = IAMPolicyTransformer(policy)
                policy_code += policy_transformer.code()
                policies_identifiers[policy['Arn']] = policy_transformer.identifier()
                entities_to_import += policy_transformer.entities_to_import()
            policies_file.write(policy_code)

        with open(f"{self._result_dir}/groups.tf", 'w') as groups_file:
            groups_code = ""
            groups_identifiers = {}
            for group in iam_raw_data['AccountGroups']:
                group_transformer = IAMGroupTransformer(group)
                groups_code += group_transformer.code()
                groups_identifiers[group['GroupName']] = group_transformer.identifier()
                entities_to_import += group_transformer.entities_to_import()
            groups_file.write(groups_code)

        user_group_memberships = {}
        with open(f"{self._result_dir}/users.tf", 'w') as users_file:
            user_code = ""
            for user in iam_raw_data['AccountUsers']:
                transformer = IAMUserTransformer(user)
                user_code += transformer.code()
                for group in user['GroupList']:
                    if group not in user_group_memberships:
                        user_group_memberships[group] = []
                    user_group_memberships[group].append(user['UserName'])
                membership_transformer = IAMUserGroupMembershipTransformer({"UserName": user['UserName'], "Groups": user['GroupList']},
                                                                           transformer.identifier())
                user_code += membership_transformer.code()
                entities_to_import += transformer.entities_to_import() + membership_transformer.entities_to_import()
            users_file.write(user_code)

        with open(f"{self._result_dir}/roles.tf", 'w') as roles_file:
            roles_code = ""
            for role in iam_raw_data['AccountRoles']:
                transformer = IAMRoleTransformer(role)
                roles_code += transformer.code()
                entities_to_import += transformer.entities_to_import()
            roles_file.write(roles_code)

        return entities_to_import

    def _create_rightsized_state(self, entities_to_write: dict):
        # TODO: implement
        # Create roles

        # Create groups
        # for group, users in user_group_memberships:
        #     groups_code += IAMGroupMembershipsTransformer({"Users": users, "GroupName": group, "GroupHcl": groups_identifiers[group]}).code()

        # Create users

        # Create policies
        pass
