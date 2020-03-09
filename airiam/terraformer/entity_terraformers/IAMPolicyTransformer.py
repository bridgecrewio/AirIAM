from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer
from airiam.terraformer.entity_terraformers.IAMPolicyDocumentTransformer import IAMPolicyDocumentTransformer


class IAMPolicyTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        super().__init__('aws_iam_policy', BaseEntityTransformer.safe_name_converter(entity_json['PolicyName']), entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        document = next(version['Document'] for version in entity_json['PolicyVersionList'] if version['IsDefaultVersion'])
        policy = IAMPolicyDocumentTransformer(document, self._safe_name)
        policy_code = f"""{policy.code()}

resource "aws_iam_policy" "{self._safe_name}" {{
  name   = "{entity_json['PolicyName']}"
  policy = {policy.identifier()}.json
}}

"""
        return policy_code
