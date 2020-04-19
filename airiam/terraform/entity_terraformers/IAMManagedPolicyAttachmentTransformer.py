from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer, Principal


class IAMManagedPolicyAttachmentTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, principal_name: str, principal_type: Principal):
        self._user_name = principal_name
        self._safe_user_name = BaseEntityTransformer.safe_name_converter(principal_name)
        self._principal = principal_type.value
        self._policy_arn = entity_json['PolicyArn']
        attachment_name = f"{self._safe_user_name}_{BaseEntityTransformer.safe_name_converter(entity_json['PolicyName'])}"
        if self.is_aws_managed(entity_json['PolicyArn']):
            attachment_name = f"{self._safe_user_name}_{BaseEntityTransformer.safe_name_converter(entity_json['PolicyName'])}_managed"
        super().__init__(f"aws_iam_{self._principal}_policy_attachment", attachment_name, entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        policy_arn = f'"{entity_json["PolicyArn"]}"'
        if not self.is_aws_managed(entity_json['PolicyArn']):
            policy_arn = f"aws_iam_policy.{BaseEntityTransformer.safe_name_converter(entity_json['PolicyName'])}.arn"

        return f"""resource "aws_iam_{self._principal}_policy_attachment" "{self._safe_name}" {{
  policy_arn = {policy_arn}
  {self._principal} = aws_iam_{self._principal}.{self._safe_user_name}.name
}}
"""

    def entities_to_import(self) -> list:
        return [{"identifier": self.identifier(), "entity": f"{self._user_name}/{self._policy_arn}"}]

    @staticmethod
    def is_aws_managed(policy_arn):
        return 'iam::aws:' in policy_arn
