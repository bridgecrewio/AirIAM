class BaseEntityTransformer:
    def __init__(self, entity_type: str, safe_name: str, entity_json: dict):
        self._entity_type = entity_type
        self._safe_name = safe_name
        self._code = self._generate_hcl2_code(entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        raise NotImplementedError()

    def code(self) -> str:
        return self._code

    def identifier(self) -> str:
        return f"{self._entity_type}.{self._safe_name}"

    @staticmethod
    def safe_name_converter(name_str: str) -> str:
        return ''.join(e for e in name_str if e.isalnum() or e == '_' or e == '-')
