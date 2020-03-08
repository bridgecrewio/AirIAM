from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer
from airiam.terraformer.entity_terraformers.IAMPolicyDocumentTransformer import IAMPolicyDocumentTransformer


class IAMPolicyTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        super().__init__('aws_iam_policy', BaseEntityTransformer.safe_name_converter(entity_json['PolicyName']))
        document = next(version['Document'] for version in entity_json['PolicyVersionList'] if version['IsDefaultVersion'])
        policy = IAMPolicyDocumentTransformer(document, self.safe_name)
        self.policy_code = f"""{policy.code()}

resource "aws_iam_policy" "{self.safe_name}" {{
  name   = "{entity_json['PolicyName']}"
  policy = {policy.identifier()}.json
}}

"""

    def code(self) -> str:
        return self.policy_code
