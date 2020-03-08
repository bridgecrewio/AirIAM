from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class AWSProviderTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict):
        super().__init__('aws_provider', 'default_provider')
        if 'profile' in entity_json and entity_json['profile'] is not None:
            self.provider_code = f"""provider "aws" {{
  region  = "{entity_json['region']}"
  profile = "{entity_json['profile']}"
}}

"""
        else:
            self.provider_code = f"""provider "aws" {{
  region = "{entity_json['region']}"
}}

"""

    def code(self) -> str:
        return self.provider_code
