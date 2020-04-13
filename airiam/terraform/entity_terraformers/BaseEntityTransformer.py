from enum import Enum


class Principal(Enum):
    User = 'user'
    Role = 'role'
    Group = 'group'


class BaseEntityTransformer:
    def __init__(self, entity_type: str, entity_name: str, entity_json: dict):
        self._entity_type = entity_type
        self._entity_name = entity_name
        self._safe_name = BaseEntityTransformer.safe_name_converter(entity_name)
        self._code = self._generate_hcl2_code(entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        raise NotImplementedError()

    def entities_to_import(self) -> list:
        return [{"identifier": self.identifier(), "entity": self._entity_name}]

    def code(self) -> str:
        return self._code

    def identifier(self) -> str:
        return f"{self._entity_type}.{self._safe_name}"

    @staticmethod
    def safe_name_converter(name_str: str) -> str:
        without_special_characters = ''.join(e for e in name_str if e.isalnum() or e == '_' or e == '-')
        if without_special_characters[0].isdigit():
            return f"_{without_special_characters}"
        return without_special_characters

    @staticmethod
    def transform_tags(entity_json: dict):
        tags = entity_json.get('Tags', [])
        tags.extend([
            {"Key": "Managed by", "Value": "AirIAM by Bridgecrew"},
            {"Key": "Managed through", "Value": "Terraform"}
        ])
        tag_str = "\n".join(map(lambda tag: f"    \"{tag['Key']}\" = \"{tag['Value']}\"", tags))
        return f"""tags = {{
{tag_str}
  }}"""
