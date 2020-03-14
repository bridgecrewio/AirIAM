from python_terraform import *

from airiam.models.RuntimeReport import RuntimeReport
from airiam.terraformer.entity_terraformers.AWSProviderTransformer import AWSProviderTransformer
from airiam.terraformer.entity_terraformers.IAMPolicyTransformer import IAMPolicyTransformer
from airiam.terraformer.entity_terraformers.IAMUserTransformer import IAMUserTransformer
from airiam.terraformer.entity_terraformers.IAMGroupTransformer import IAMGroupTransformer
from airiam.terraformer.entity_terraformers.IAMGroupMembershipsTransformer import IAMGroupMembershipsTransformer
from airiam.terraformer.entity_terraformers.IAMRoleTransformer import IAMRoleTransformer

current_dir = os.path.abspath(os.path.dirname(__file__))
boilerplate_files = ["admins.tf", "developers.tf", "power_users.tf"]


class TerraformTransformer:
    def __init__(self, logger, profile=None, result_dir='.'):
        self.logger = logger
        self.profile = profile
        self._result_dir = result_dir

    def transform(self, results, should_import=True) -> str:
        """
        Creates terraform files from the setup it receives
        :param results: IAM scan results
        :type results: RuntimeReport
        :param should_import: For testing only
        :return:
        """
        try:
            entities_to_import = self._create_current_state(results.get_raw_data())

            if should_import:
                tf = Terraform()
                tf.init(backend=False)
                for entity_to_import in entities_to_import:
                    print(f"Importing {entity_to_import['entity']} to {entity_to_import['identifier']}")
                    return_code, stdout, stderr = tf.import_cmd(entity_to_import['identifier'], entity_to_import['entity'])
                    if return_code != 0:
                        self.logger.error(f"Error: {stderr}")
                return "Success"
        except Exception as e:
            self.logger.error(e)
            raise e

    def _create_current_state(self, iam_raw_data: dict) -> list:
        entities_to_import = []
        with open('main.tf', 'w') as main_file:
            main_code = AWSProviderTransformer({'region': 'us-east-1', 'profile': self.profile}).code()
            main_file.write(main_code)

        policies_identifiers = {}

        with open('policies.tf', 'w') as policies_file:
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

        user_group_memberships = {}
        with open('users.tf', 'w') as users_file:
            user_code = ""
            for user in iam_raw_data['AccountUsers']:
                transformer = IAMUserTransformer(user)
                user_code += transformer.code()
                entities_to_import += transformer.entities_to_import()
                for group in user['GroupList']:
                    if group not in user_group_memberships:
                        user_group_memberships[group] = []
                    user_group_memberships[group].append(user['UserName'])
            users_file.write(user_code)

        with open('groups.tf', 'w') as groups_file:
            groups_code = ""
            groups_identifiers = {}
            for group in iam_raw_data['AccountGroups']:
                group_transformer = IAMGroupTransformer(group)
                groups_code += group_transformer.code()
                groups_identifiers[group['GroupName']] = group_transformer.identifier()
                entities_to_import += group_transformer.entities_to_import()

            for group, users in user_group_memberships.items():
                groups_code += IAMGroupMembershipsTransformer({"Users": users, "GroupName": group, "GroupHcl": groups_identifiers[group]}).code()
            groups_file.write(groups_code)

        with open('roles.tf', 'w') as roles_file:
            roles_code = ""
            for role in iam_raw_data['AccountRoles']:
                transformer = IAMRoleTransformer(role)
                roles_code += transformer.code()
                entities_to_import += transformer.entities_to_import()
            roles_file.write(roles_code)

        return entities_to_import
