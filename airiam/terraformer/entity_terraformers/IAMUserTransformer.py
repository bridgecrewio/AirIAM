from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class IAMUserTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        super().__init__('aws_iam_user', BaseEntityTransformer.safe_name_converter(entity_json['UserName']), entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        return f"""resource "aws_iam_user" "{self._safe_name}" {{
  name          = "{entity_json['UserName']}"
  path          = "{entity_json['Path']}"
  force_destroy = true
  tags          = {{
    "Managed by" = "Bridgecrew's AirIAM"
    "Managed through" = "Terraform"
  }}  
}}

"""
