import json
import re
import requests

ACTION_TABLE_URL = 'https://raw.githubusercontent.com/salesforce/policy_sentry/8d480b572d0431c37fd21ccb02555327429c09c4/policy_sentry/shared/data/iam-definition.json'
ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR = ['iam:PassRole', 's3:GetObject', 's3:PutObject']

action_map = {a['prefix']: a for a in requests.get(ACTION_TABLE_URL).json()}


class PolicyAnalyzer:
    @staticmethod
    def convert_to_list(list_or_single_object):
        if isinstance(list_or_single_object, list):
            return list_or_single_object
        return [list_or_single_object]

    @staticmethod
    def _get_policy_actions(policy_document: dict):
        policy_statements = PolicyAnalyzer.convert_to_list(policy_document['Statement'])
        actions_list = []
        for statement in policy_statements:
            if statement['Effect'] == 'Allow':
                actions_list.extend(PolicyAnalyzer.convert_to_list(statement['Action']))
        return actions_list

    @staticmethod
    def is_policy_unused(policy_document: dict, services_last_accessed: list) -> bool:
        statements_str = json.dumps(policy_document['Statement'])
        if '"Effect": "Deny"' in statements_str or '"NotAction":' in statements_str:
            # If statement contains a "Deny" effect - Access Advisor won't detect that action because it is a restriction
            # If statement contains a "NotAction" effect - Access Advisor won't detect usage of this policy correctly
            return False

        policy_actions = PolicyAnalyzer._get_policy_actions(policy_document)
        if len([action for action in policy_actions if
                len(list(filter(re.compile(action.replace('*', '.*')).match, ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR))) > 0]) > 0:
            return False

        services_accessed_through_policy = list(set(map(lambda action: action.split(':')[0], policy_actions)))
        return len(
            [service for service in services_accessed_through_policy if
             len(list(filter(re.compile(service.replace('*', '.*')).match, services_last_accessed))) > 0
             ]) == 0

    @staticmethod
    def policy_is_write_access(policy_document):
        actions = PolicyAnalyzer._get_policy_actions(policy_document)
        for action in actions:
            if action == '*' or '*' in action.split(':'):
                return True
            [action_service, action_name] = action.split(':')
            try:
                action_regex = action_name.replace('*', '.*')
                action_objs = list(filter(lambda privilege_obj: re.match(action_regex, privilege_obj['privilege']),
                                          action_map[action_service]['privileges']))
            except StopIteration:
                action_objs = []

            for action_obj in action_objs:
                if action_obj['access_level'] in ['Write', 'Delete', 'Permissions management']:
                    return True
        return False
