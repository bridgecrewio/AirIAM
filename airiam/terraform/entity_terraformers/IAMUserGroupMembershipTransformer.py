import json

from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class IAMUserGroupMembershipTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, user_identifier: str):
        self._user_identifier = user_identifier
        self._user_name = entity_json['UserName']
        self._groups = entity_json['Groups']
        super().__init__('aws_iam_user_group_membership', f"{entity_json['UserName']}_group_attachment", entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        return f"""resource {self._entity_type} "{self._safe_name}" {{
  user = {self._user_identifier}.name

  groups = {json.dumps(entity_json['Groups'])}
}}
"""

    def entities_to_import(self) -> list:
        return [{"identifier": self.identifier(), "entity": f"{self._user_name}/{'/'.join(self._groups)}"}]
