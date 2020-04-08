from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer, Principal
from airiam.terraform.entity_terraformers.IAMInlinePolicyTransformer import IAMInlinePolicyTransformer
from airiam.terraform.entity_terraformers.IAMManagedPolicyAttachmentTransformer import IAMManagedPolicyAttachmentTransformer


class IAMUserTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        self.sub_entities_to_import = []
        super().__init__('aws_iam_user', entity_json['UserName'], entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        user_policies_code = ""
        managed_policies_code = ""

        for inline_policy in entity_json.get('UserPolicyList', []):
            inline_policy_obj = IAMInlinePolicyTransformer(inline_policy, self._safe_name, Principal.User)
            user_policies_code += inline_policy_obj.code()
            self.sub_entities_to_import += inline_policy_obj.entities_to_import()

        for managed_policy in entity_json.get('AttachedManagedPolicies', []):
            managed_policy_obj = IAMManagedPolicyAttachmentTransformer(managed_policy, self._entity_name, Principal.User)
            managed_policies_code += managed_policy_obj.code()
            self.sub_entities_to_import += managed_policy_obj.entities_to_import()

        tags = BaseEntityTransformer.transform_tags(entity_json)
        return f"""resource "aws_iam_user" "{self._safe_name}" {{
  name          = "{entity_json['UserName']}"
  path          = "{entity_json['Path']}"
  force_destroy = true
  
  {tags}
}}
{user_policies_code}{managed_policies_code}"""

    def entities_to_import(self) -> list:
        return super().entities_to_import() + self.sub_entities_to_import
