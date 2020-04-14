from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer, Principal
from airiam.terraform.entity_terraformers.IAMPolicyDocumentTransformer import IAMPolicyDocumentTransformer


class IAMInlinePolicyTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, principal_name: str, principal: Principal):
        policy_name = BaseEntityTransformer.safe_name_converter(entity_json['PolicyName'])
        self.principal_name = principal_name
        self._safe_user_name = BaseEntityTransformer.safe_name_converter(self.principal_name)
        self._principal = principal.value
        super().__init__(f"aws_iam_{principal.value}_policy", policy_name, entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        policy_document_hcl = IAMPolicyDocumentTransformer(entity_json['PolicyDocument'], f"{self._safe_name}_document", self.principal_name)
        return f"""resource "aws_iam_{self._principal}_policy" "{self.principal_name}_{self._safe_name}" {{
  name   = "{entity_json['PolicyName']}"
  policy = {policy_document_hcl.identifier()}.json
  {self._principal}   = aws_iam_{self._principal}.{self._safe_user_name}.name
}}

{policy_document_hcl.code()}
"""

    def entities_to_import(self) -> list:
        return [{"identifier": f"aws_iam_{self._principal}_policy.{self.principal_name}_{self._safe_name}", "entity": f"{self.principal_name}:{self._entity_name}"}]
