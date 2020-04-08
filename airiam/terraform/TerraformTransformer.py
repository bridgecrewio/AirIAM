from python_terraform import *
import copy

from airiam.models import RuntimeReport
from airiam.terraform.entity_terraformers.AWSProviderTransformer import AWSProviderTransformer
from airiam.terraform.entity_terraformers.IAMGroupTransformer import IAMGroupTransformer
from airiam.terraform.entity_terraformers.IAMPolicyTransformer import IAMPolicyTransformer
from airiam.terraform.entity_terraformers.IAMRoleTransformer import IAMRoleTransformer
from airiam.terraform.entity_terraformers.IAMUserGroupMembershipTransformer import IAMUserGroupMembershipTransformer
from airiam.terraform.entity_terraformers.IAMUserTransformer import IAMUserTransformer

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

    def transform(self, results: RuntimeReport, without_unused: bool, without_groups: bool, should_import: bool) -> str:
        try:
            entities_to_transform = self._list_entities_to_transform(results, without_unused, without_groups)

            tf = Terraform(working_dir=self._result_dir)
            tf.init(backend=False)
            if should_import:
                num_of_entities_to_import = len(entities_to_transform)
                print(f"Importing {num_of_entities_to_import} entities")
                i = 1
                for entity_to_import in entities_to_transform:
                    msg = f"#{i} of {num_of_entities_to_import}: Importing {entity_to_import['entity']} to {entity_to_import['identifier']}"
                    print(ERASE_LINE + f"\r{msg}", end="")
                    return_code, stdout, stderr = tf.import_cmd(entity_to_import['identifier'], entity_to_import['entity'])
                    if return_code != 0 and 'Resource already managed by Terraform' not in stderr:
                        self.logger.error(f"Error: {stderr}")
                    i += 1
                print("Imported all existing entities to state")

            tf.fmt()
            return results
        except Exception as e:
            self.logger.error(e)
            raise e

    def _list_entities_to_transform(self, report: RuntimeReport, without_unused: bool, without_consolidated_groups: bool) -> list:
        iam_raw_data = report.get_raw_data()
        raw_entities_to_transform = {
            'Users': copy.deepcopy(iam_raw_data['AccountUsers']),
            'Roles': copy.deepcopy(iam_raw_data['AccountRoles']),
            'Policies': copy.deepcopy(iam_raw_data['AccountPolicies']),
            'Groups': copy.deepcopy(iam_raw_data['AccountGroups'])
        }
        if without_unused:
            report.get_unused()
            # todo: filter out entities
            # todo: remove unused attachments from migrated entities\
            # todo: Log a warning what won't be migrated
            pass

        if not without_consolidated_groups:
            # todo: iterate over users fix group attachments
            # todo: if without_unused, delete older groups
            pass

        entities_to_import = []
        with open(f"{self._result_dir}/main.tf", 'w') as main_file:
            main_code = AWSProviderTransformer({'region': 'us-east-1', 'profile': self.profile}).code()
            main_file.write(main_code)

        policies_identifiers = {}

        with open(f"{self._result_dir}/policies.tf", 'w') as policies_file:
            policy_code = ""
            for policy in raw_entities_to_transform['Policies']:
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
            for group in raw_entities_to_transform['Groups']:
                group_transformer = IAMGroupTransformer(group)
                groups_code += group_transformer.code()
                groups_identifiers[group['GroupName']] = group_transformer.identifier()
                entities_to_import += group_transformer.entities_to_import()
            groups_file.write(groups_code)

        user_group_memberships = {}
        with open(f"{self._result_dir}/users.tf", 'w') as users_file:
            user_code = ""
            for user in raw_entities_to_transform['Users']:
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
            for role in raw_entities_to_transform['Roles']:
                transformer = IAMRoleTransformer(role)
                roles_code += transformer.code()
                entities_to_import += transformer.entities_to_import()
            roles_file.write(roles_code)

        return entities_to_import
