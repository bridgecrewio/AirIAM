class BaseEntityTransformer:
    def __init__(self, entity_type: str, safe_name: str):
        self.entity_type = entity_type
        self.safe_name = safe_name

    def code(self) -> str:
        raise NotImplementedError()

    def identifier(self) -> str:
        return f"{self.entity_type}.{self.safe_name}"

    @staticmethod
    def safe_name_converter(name_str: str) -> str:
        return ''.join(e for e in name_str if e.isalnum() or e == '_' or e == '-')
