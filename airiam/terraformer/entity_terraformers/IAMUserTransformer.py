from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class IAMUserTransformer(BaseEntityTransformer):
    def __init__(self, entity_json):
        super().__init__('aws_iam_user', BaseEntityTransformer.safe_name_converter(entity_json['UserName']))
        self.user_code = f"""resource "aws_iam_user" "{self.safe_name}" {{
  name          = "{entity_json['UserName']}"
  path          = "{entity_json['Path']}"
  force_destroy = true
  tags          = {{
    "Managed by" = "Bridgecrew's AirIAM"
    "Managed through" = "Terraform"
  }}  
}}

"""

    def code(self) -> str:
        return self.user_code
