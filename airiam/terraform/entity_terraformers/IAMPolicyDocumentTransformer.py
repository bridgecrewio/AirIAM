import json

from airiam.terraform.entity_terraformers.BaseEntityTransformer import BaseEntityTransformer


class IAMPolicyDocumentTransformer(BaseEntityTransformer):
    def __init__(self, entity_json: dict, policy_name, principal_name=None):
        policy_document_name = f"{policy_name}_document"
        if principal_name:
            policy_document_name = f"{principal_name}_{policy_document_name}"
        super().__init__('data.aws_iam_policy_document', policy_document_name, entity_json)

    def _generate_hcl2_code(self, entity_json) -> str:
        statements = IAMPolicyDocumentTransformer.force_list(entity_json['Statement'])
        if 'Principal' in statements[0]:
            statements = self.transform_assume_policy_statements(statements)
        else:
            statements = self.transform_execution_policy(statements)
        code = f"""data "aws_iam_policy_document" "{self._safe_name}" {{
  version = "{entity_json.get('Version', '2012-10-17')}"
{statements}}}"""
        return code

    @staticmethod
    def transform_execution_policy(statements):
        statement_block = ""
        for statement in statements:
            sid_string = ""
            if statement.get('Sid', '') != '':
                sid_string = f"sid    = \"{statement['Sid']}\"\n    "

            actions = IAMPolicyDocumentTransformer.force_list(statement.get('Action'))
            if 'Action' in statement:
                action_str = f"actions = {json.dumps(actions)}"
            else:
                actions = IAMPolicyDocumentTransformer.force_list(statement.get('NotAction'))
                action_str = f"not_actions = {json.dumps(actions)}"
            condition_block = IAMPolicyDocumentTransformer.transform_conditions(statement)
            resources_list_str = json.dumps(IAMPolicyDocumentTransformer.force_list(statement.get('Resource'))).replace('${', '$\\u0024{')
            statement_block += f"""  statement {{
    {sid_string}effect    = "{statement['Effect']}"
    {action_str}
    resources = {resources_list_str}
    {condition_block}
  }}
"""

        return statement_block

    @staticmethod
    def transform_assume_policy_statements(statements):
        statement_block = ""
        for statement in statements:
            sid_string = ""
            if statement.get('Sid', '') != '':
                sid_string = f"sid    = \"{statement['Sid']}\"\n    "
            condition_block = IAMPolicyDocumentTransformer.transform_conditions(statement)

            statement_block += f"""  statement {{
    {sid_string}effect  = "{statement['Effect']}"
    actions = {json.dumps(IAMPolicyDocumentTransformer.force_list(statement['Action']))}
    principals {{
      type        = "{list(statement['Principal'].keys())[0]}"
      identifiers = {json.dumps(IAMPolicyDocumentTransformer.force_list(statement['Principal'][list(statement['Principal'].keys())[0]]))}
    }}
  {condition_block}}}
"""

        return statement_block

    @staticmethod
    def transform_conditions(statement):
        condition_block = ""
        if 'Condition' in statement:
            for test, items in statement['Condition'].items():
                for variable, values in items.items():
                    values_str = json.dumps(IAMPolicyDocumentTransformer.force_list(values)).replace('${', '$\\u0024{')
                    condition_block += f"""
    condition {{
      test     = "{test}"
      variable = "{variable}"
      values   = {values_str}
    }}
  """
        return condition_block

    @staticmethod
    def force_list(x):
        if isinstance(x, list):
            return x
        return [x]

    def entities_to_import(self) -> list:
        return []
