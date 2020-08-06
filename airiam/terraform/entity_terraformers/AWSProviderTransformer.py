from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class AWSProviderTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict):
        super().__init__('aws_provider', 'default_provider', entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        if 'profile' in entity_json and entity_json['profile'] is not None:
            provider_code = f"""provider "aws" {{
  region  = "{entity_json['region']}"
  profile = "{entity_json['profile']}"
  version = "~> 2.0"
}}

"""
        else:
            provider_code = f"""provider "aws" {{
  region = "{entity_json['region']}"
}}

"""
        return provider_code

    def entities_to_import(self) -> list:
        return []
