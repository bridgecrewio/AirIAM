from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer
from airiam.terraform.entity_terraformers.IAMPolicyDocumentTransformer import IAMPolicyDocumentTransformer


class IAMPolicyTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        super().__init__('aws_iam_policy', entity_json['PolicyName'], entity_json)
        self._policy_arn = entity_json['Arn']

    def _generate_hcl2_code(self, entity_json) -> str:
        document = next(version['Document'] for version in entity_json['PolicyVersionList'] if version['IsDefaultVersion'])
        policy = IAMPolicyDocumentTransformer(document, self._safe_name)
        tags = BaseEntityTransformer.transform_tags(entity_json)
        policy_code = f"""{policy.code()}

resource "aws_iam_policy" "{self._safe_name}" {{
  name        = "{entity_json['PolicyName']}"
  path        = "{entity_json['Path']}"
  policy      = {policy.identifier()}.json
  description = \"{entity_json['Description']}\"
}}

"""
        return policy_code

    def entities_to_import(self) -> list:
        return [{"identifier": self.identifier(), "entity": self._policy_arn}]
