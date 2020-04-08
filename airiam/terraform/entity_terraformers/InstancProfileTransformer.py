from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class InstanceProfileTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, role_identifier: str):
        self.raw_name = entity_json['Arn'].split('/')[-1]
        self._role_identifier = role_identifier
        super().__init__('aws_iam_instance_profile', BaseEntityTransformer.safe_name_converter(self.raw_name), entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        tags = self.transform_tags(entity_json)

        return f"""resource "{self._entity_type}" "{self._safe_name}" {{
  name = "{self.raw_name}"
  path = "{entity_json['Path']}"
  role = {self._role_identifier}.name
}}

"""
