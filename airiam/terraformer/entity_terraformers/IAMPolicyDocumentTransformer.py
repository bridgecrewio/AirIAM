import json

from airiam.terraformer.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class IAMPolicyDocumentTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, policy_name):
        super().__init__('data.aws_iam_policy_document', f"{policy_name}_document", entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        statements = IAMPolicyDocumentTransformer.force_list(entity_json['Statement'])
        if 'Principal' in statements[0]:
            statements = self.transform_assume_policy_statements(statements)
        else:
            statements = self.transform_execution_policy(statements)
        code = f"""data "aws_iam_policy_document" "{self._safe_name}" {{
  version = "{entity_json.get('Version', '2012-10-17')}"
{statements}
}}"""
        return code

    @staticmethod
    def transform_execution_policy(statements):
        statement_block = ""
        for statement in statements:
            sid_string = ""
            if statement.get('Sid', '') != '':
                sid_string = f"sid    = \"{statement['Sid']}\"\n    "
            statement_block += f"""  statement {{
    {sid_string}effect = "{statement['Effect']}"
    action = {json.dumps(statement['Action'])}
  }}
"""

        return statement_block

    @staticmethod
    def transform_assume_policy_statements(statements):
        statement_block = ""
        for statement in statements:
            statement_block += f"""  statement {{
            effect = "{statement['Effect']}"
            action = "{statement['Action']}"
            principals {{
              type        = "{list(statement['Principal'].keys())[0]}"
              identifiers = {json.dumps(list(statement['Principal'].values()))}
            }} 
          }}
        """

        return statement_block

    @staticmethod
    def force_list(x):
        if isinstance(x, list):
            return x
        return [x]