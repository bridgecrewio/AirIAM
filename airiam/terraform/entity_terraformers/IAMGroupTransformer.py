from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer, Principal
from airiam.terraform.entity_terraformers.IAMInlinePolicyTransformer import IAMInlinePolicyTransformer
from airiam.terraform.entity_terraformers.IAMManagedPolicyAttachmentTransformer import IAMManagedPolicyAttachmentTransformer


class IAMGroupTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict):
        self._sub_entities_to_import = []
        super().__init__('aws_iam_group', BaseEntityTransformer.safe_name_converter(entity_json['GroupName']), entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        group_policies = ""
        managed_policies = ""

        for inline_policy in entity_json.get('UserPolicyList', []):
            transformer = IAMInlinePolicyTransformer(inline_policy, self._safe_name, Principal.Group)
            group_policies += transformer.code()
            self._sub_entities_to_import += transformer.entities_to_import()

        for managed_policy in entity_json.get('AttachedManagedPolicies', []):
            transformer = IAMManagedPolicyAttachmentTransformer(managed_policy, self._safe_name, Principal.Group)
            managed_policies += transformer.code()
            self._sub_entities_to_import += transformer.entities_to_import()

        tags = BaseEntityTransformer.transform_tags(entity_json)
        return f"""resource "aws_iam_group" "{self._safe_name}" {{
  name = "{entity_json['GroupName']}"
  path = "{entity_json['Path']}"
}}

{group_policies}
{managed_policies}
"""

    def entities_to_import(self) -> list:
        return super().entities_to_import() + self._sub_entities_to_import
