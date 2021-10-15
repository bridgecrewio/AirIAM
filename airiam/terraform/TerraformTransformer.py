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

    def transform(self, results: RuntimeReport, without_unused: bool, without_groups: bool, without_import: bool) -> (dict, str):
        try:
            if not without_groups:
                # todo: implement!
                self.logger.warning('Migrating to the recommended groups isn\'t supported yet. Issue exists - '
                                    'https://github.com/bridgecrewio/AirIAM/issues/20')
                self.logger.warning('Will use the existing groups for terraform migration until it is implemented')
            entities_to_transform = self._list_entities_to_transform(results, without_unused, without_groups)
            entities_to_import = self.write_terraform_code(entities_to_transform)
            tf = Terraform(working_dir=self._result_dir)
            print("Initializing terraform")
            tf.init(backend=False)
            tf.fmt()
            if not without_import:
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

            return entities_to_transform, self._result_dir
        except Exception as e:
            self.logger.error(e, stack_info=True)
            raise e

    def _list_entities_to_transform(self, report: RuntimeReport, without_unused: bool, without_consolidated_groups: bool) -> dict:
        iam_raw_data = report.get_raw_data()
        raw_entities_to_transform = {
            'Users': copy.copy(iam_raw_data['AccountUsers']),
            'Roles': copy.copy(iam_raw_data['AccountRoles']),
            'Policies': copy.copy(iam_raw_data['AccountPolicies']),
            'Groups': copy.copy(iam_raw_data['AccountGroups'])
        }
        if without_unused:
            unused = report.get_unused()
            unused_entities = unused['Users'] + unused['Roles'] + unused['Policies'] + unused['Groups'] + unused['PolicyAttachments']
            self.logger.warning(f'Filtering out {len(unused_entities)} entities from terraform. These entities will have to be handled manually')
            for user in unused['Users']:
                raw_entities_to_transform['Users'].remove(user)
            for role in unused['Roles']:
                raw_entities_to_transform['Roles'].remove(role)
            for group in unused['Groups']:
                raw_entities_to_transform['Groups'].remove(group)
            for policy in unused['Policies']:
                raw_entities_to_transform['Policies'].remove(policy)
            for policy_attachment_obj in unused['PolicyAttachments']:
                if 'Role' in policy_attachment_obj:
                    TerraformTransformer.remove_from_transformation(policy_attachment_obj, raw_entities_to_transform, 'Role')
                elif 'User' in policy_attachment_obj:
                    TerraformTransformer.remove_from_transformation(policy_attachment_obj, raw_entities_to_transform, 'User')
                elif 'Group' in policy_attachment_obj:
                    TerraformTransformer.remove_from_transformation(policy_attachment_obj, raw_entities_to_transform, 'Group')

        # todo: iterate over users fix group attachments
        # todo: if without_unused, delete older groups
        # if not without_consolidated_groups:

        return raw_entities_to_transform

    @staticmethod
    def remove_from_transformation(policy_attachment_obj: dict, entity_dict: dict, principal_type: str):
        """
        This method removes the policy attachment from the entity list. It relies heavily on the reuse of the structures by AWS and AirIAM:
        The entity list will always be named the <principal_type>s, e.g. Users/Roles/Groups
        The key for the inline policy list will always be named <principal_type>PolicyList, e.g. RolePolicyList / UserPolicyList
        The key for the principal_id will be the principal_type itself, i.e. Group / User / Role
        :param policy_attachment_obj: A dict which contains one of the following keys: User, Role, Group
        :param entity_dict:           A dict which holds all the entities as lists with the relevant key being the principal_type
        :param principal_type:        One of: User / Role / Group
        """
        policy_id = policy_attachment_obj['PolicyArn']
        principal = next(p for p in entity_dict[f'{principal_type}s'] if p[f'{principal_type}Name'] == policy_attachment_obj[principal_type])
        if policy_id.startswith('arn:aws'):
            policy_attachment = next(policy for policy in principal['AttachedManagedPolicies']
                                     if policy['PolicyArn'] == policy_attachment_obj['PolicyArn'])
            principal['AttachedManagedPolicies'].remove(policy_attachment)
        else:
            policy_attachment = next(policy for policy in principal[f'{principal_type}PolicyList']
                                     if policy['PolicyName'] == (policy_attachment_obj.get('PolicyName') or policy_attachment_obj.get('PolicyArn')))
            principal[f'{principal_type}PolicyList'].remove(policy_attachment)

    def write_terraform_code(self, iam_entities: dict) -> list:
        entities_to_import = []
        with open(f"{self._result_dir}/main.tf", 'w') as main_file:
            main_code = AWSProviderTransformer({'region': 'us-east-1', 'profile': self.profile}).code()
            main_file.write(main_code)

        policies_identifiers = {}

        with open(f"{self._result_dir}/policies.tf", 'w') as policies_file:
            policy_code = ""
            for policy in iam_entities['Policies']:
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
            for group in iam_entities['Groups']:
                group_transformer = IAMGroupTransformer(group)
                groups_code += group_transformer.code()
                groups_identifiers[group['GroupName']] = group_transformer.identifier()
                entities_to_import += group_transformer.entities_to_import()
            groups_file.write(groups_code)

        user_group_memberships = {}
        with open(f"{self._result_dir}/users.tf", 'w') as users_file:
            user_code = ""
            for user in iam_entities['Users']:
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
            for role in iam_entities['Roles']:
                transformer = IAMRoleTransformer(role)
                roles_code += transformer.code()
                entities_to_import += transformer.entities_to_import()
            roles_file.write(roles_code)

        return entities_to_import
