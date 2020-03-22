import datetime as dt
import pandas as pd
import json

ACTION_TABLE_URL = 'https://raw.githubusercontent.com/salesforce/policy_sentry/master/policy_sentry/shared/data/action_table.csv'
ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR = ['iam:PassRole']


class BaseOrganizer:
    def __init__(self):
        action_table = pd.read_csv(ACTION_TABLE_URL, delimiter=";").to_dict('records')
        self.action_map = {}
        for action_obj in action_table:
            if action_obj['service'] not in self.action_map:
                self.action_map[action_obj['service']] = []
            self.action_map[action_obj['service']].append(action_obj)

    @staticmethod
    def convert_to_list(list_or_single_object):
        if isinstance(list_or_single_object, list):
            return list_or_single_object
        return [list_or_single_object]

    @staticmethod
    def days_from_today(str_date_from_today):
        if str_date_from_today in ['no_information', 'N/A']:
            return 365
        date = dt.datetime.fromisoformat(str_date_from_today).replace(tzinfo=None)
        delta = dt.datetime.now() - date

        return delta.days

    @staticmethod
    def _get_policy_actions(policy_document: dict):
        policy_statements = BaseOrganizer.convert_to_list(policy_document['Statement'])
        actions_list = []
        for statement in policy_statements:
            if statement['Effect'] == 'Allow':
                actions_list.extend(BaseOrganizer.convert_to_list(statement['Action']))
        return actions_list

    @staticmethod
    def is_policy_unused(policy_document: dict, services_last_accessed: list) -> bool:
        statements_str = json.dumps(policy_document['Statement'])
        if '"Effect": "Deny"' in statements_str or '"NotAction":' in statements_str:
            # If statement contains a "Deny" effect - Access Advisor won't detect that action because it is a restriction
            # If statement contains a "NotAction" effect - Access Advisor won't detect usage of this policy correctly
            return False

        policy_actions = BaseOrganizer._get_policy_actions(policy_document)
        if len([action for action in policy_actions if action in ACTIONS_NOT_COVERED_BY_ACCESS_ADVISOR]) > 0:
            return False

        services_accessed_through_policy = list(set(map(lambda action: action.split(':')[0], policy_actions)))
        return len([service for service in services_accessed_through_policy if service in services_last_accessed]) == 0
