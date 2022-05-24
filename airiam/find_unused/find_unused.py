import copy
import datetime as dt
import logging
from datetime import timezone

from airiam.find_unused.PolicyAnalyzer import PolicyAnalyzer
from airiam.find_unused.RuntimeIamScanner import RuntimeIamScanner


def filter_attachments_of_unused_entities(unused_policy_attachments, unused_users, unused_roles,
                                          redundant_groups) -> list:
    unused_role_names = list(map(lambda role_obj: role_obj['RoleName'], unused_roles))
    unused_user_names = list(map(lambda user_obj: user_obj['UserName'], unused_users))
    redundant_group_names = list(map(lambda group_obj: group_obj['GroupName'], redundant_groups))
    unused_policy_attachments_of_in_use_principals = []
    for policy_attachment_obj in unused_policy_attachments:
        if 'Role' in policy_attachment_obj:
            if policy_attachment_obj['Role'] not in unused_role_names:
                unused_policy_attachments_of_in_use_principals.append(policy_attachment_obj)
        elif 'User' in policy_attachment_obj:
            if policy_attachment_obj['User'] not in unused_user_names:
                unused_policy_attachments_of_in_use_principals.append(policy_attachment_obj)
        elif 'Group' in policy_attachment_obj:
            if policy_attachment_obj['Group'] not in redundant_group_names:
                unused_policy_attachments_of_in_use_principals.append(policy_attachment_obj)

    return unused_policy_attachments_of_in_use_principals


def filter_credentials_of_unused_users(unused_active_access_keys, unused_console_login_profiles, unused_users) -> (
                                       list, list):
    result_access_keys = []
    result_console_logins = []
    for access_key in unused_active_access_keys:
        is_belong_to_unused_user = len(
            list(filter(lambda user: user['UserName'] == access_key['User'], unused_users))) > 0
        if not is_belong_to_unused_user:
            result_access_keys.append(access_key)
    for console_login in unused_console_login_profiles:
        is_belong_to_unused_user = len(
            list(filter(lambda user: user['UserName'] == console_login['User'], unused_users))) > 0
        if not is_belong_to_unused_user:
            result_console_logins.append(console_login)
    return result_access_keys, result_console_logins


def find_unused(logger, profile, refresh_cache, unused_threshold, command):
    iam_report = RuntimeIamScanner(logger, profile, refresh_cache).evaluate_runtime_iam(True, command)
    raw_iam_data = iam_report.get_raw_data()
    credential_report = raw_iam_data['CredentialReport']
    account_users = raw_iam_data['AccountUsers']
    account_roles = raw_iam_data['AccountRoles']
    account_policies = raw_iam_data['AccountPolicies']
    account_groups = raw_iam_data['AccountGroups']
    unused_users, used_users = find_unused_users(account_users, credential_report, unused_threshold)
    unused_active_access_keys, unused_console_login_profiles = find_unused_active_credentials(account_users,
                                                                                              credential_report,
                                                                                              unused_threshold)
    unattached_policies = find_unattached_policies(account_policies)
    redundant_groups = find_redundant_groups(account_groups, account_users)
    unused_roles, used_roles = find_unused_roles(account_roles, unused_threshold)
    unused_policy_attachments = find_unused_policy_attachments(account_users, account_roles, account_policies,
                                                               account_groups, unused_threshold)

    unused_access_keys, unused_console_access = filter_credentials_of_unused_users(unused_active_access_keys,
                                                                                   unused_console_login_profiles,
                                                                                   unused_users)
    unused_policy_attachments = filter_attachments_of_unused_entities(unused_policy_attachments, unused_users,
                                                                      unused_roles, redundant_groups)

    iam_report.set_unused(unused_users, unused_roles, unused_access_keys, unused_console_access, unattached_policies,
                          redundant_groups, unused_policy_attachments)
    return iam_report


def find_unused_users(users, credential_report, unused_threshold) -> (list, list):
    unused_users = []
    used_users = []
    for user in users:
        credentials = next((creds for creds in credential_report if creds['user'] == user['UserName']), {})

        findMinimumUsed = [
            days_from_today(credentials.get('access_key_1_last_used_date', 'N/A')),
            days_from_today(credentials.get('access_key_2_last_used_date', 'N/A')),
            days_from_today(credentials.get('password_last_used', 'N/A'))
        ]
        try:
            # Needs to be >= here not just >, as we need to catch "0" for accessed "today", which will fail both if
            # and elif below and put the user into "used_users" so any unused keys can be caught later.
            last_used_in_days = min(i for i in findMinimumUsed if i >= 0)
        except:
            last_used_in_days = min(i for i in findMinimumUsed if i < 0)

        if last_used_in_days >= unused_threshold:
            user['LastUsed'] = last_used_in_days
            unused_users.append(user)
        elif last_used_in_days < 0:
            user['LastUsed'] = last_used_in_days
            unused_users.append(user)
        else:
            user['LastUsed'] = last_used_in_days
            used_users.append(user)
    return unused_users, used_users


def find_unused_active_credentials(users, credential_report, unused_threshold) -> (list, list):
    unused_access_keys = []
    unused_console_login_profiles = []
    for user in users:
        try:
            credentials = next(creds for creds in credential_report if creds['user'] == user['UserName'])
        except StopIteration:
            logging.warning(f'Failed to find credentials for user {user["UserName"]}, skipping this user')
            continue
        access_key_1_unused_days = days_from_today(credentials.get('access_key_1_last_used_date', 'N/A'))
        if ((credentials['access_key_1_active'] == 'true') and (
                (access_key_1_unused_days < 0) or (access_key_1_unused_days >= unused_threshold))):
            unused_access_keys.append(
                {'User': user['UserName'], 'AccessKey': '1', 'DaysSinceLastUse': access_key_1_unused_days})

        access_key_2_unused_days = days_from_today(credentials.get('access_key_2_last_used_date', 'N/A'))
        if ((credentials['access_key_2_active'] == 'true') and (
                (access_key_2_unused_days < 0) or (access_key_2_unused_days >= unused_threshold))):
            unused_access_keys.append(
                {'User': user['UserName'], 'AccessKey': '2', 'DaysSinceLastUse': access_key_2_unused_days})

        days_since_password_last_used = days_from_today(credentials.get('password_last_used', 'N/A'))
        if ((credentials['password_enabled'] == 'true') and (
                (days_since_password_last_used < 0) or (days_since_password_last_used >= unused_threshold))):
            unused_console_login_profiles.append(
                {'User': user['UserName'], 'MFAEnabled': credentials['mfa_active'] == 'true',
                 'DaysSinceLastUse': days_since_password_last_used})
    return unused_access_keys, unused_console_login_profiles


def find_unused_roles(roles, unused_threshold) -> (list, list):
    unused_roles = []
    used_roles = []
    for role in roles:
        if role.get('LastAccessed') is None:
            used_roles.append(role)
        elif len(role['LastAccessed']) == 0:
            role['LastUsed'] = -1
            unused_roles.append(role)
        else:
            last_used = max(map(lambda last_access: last_access['LastAccessed'], role.get('LastAccessed', [])))
            role['LastUsed'] = days_from_today(last_used)
            if (role['LastUsed'] < 0) or (role['LastUsed'] >= unused_threshold):
                unused_roles.append(role)
            else:
                used_roles.append(role)
    return unused_roles, used_roles


def find_unattached_policies(policies) -> list:
    return list(filter(lambda policy: policy['AttachmentCount'] == 0 and policy['PermissionsBoundaryUsageCount'] == 0,
                       policies))


def find_redundant_groups(groups, users) -> list:
    groups_with_no_active_members = _find_groups_with_no_members(groups, users)
    groups_with_no_privilege = list(
        filter(lambda g: len(g['AttachedManagedPolicies'] + g['GroupPolicyList']) == 0, groups))
    return list({v['GroupName']: v for v in groups_with_no_active_members + groups_with_no_privilege}.values())


def _find_groups_with_no_members(group_list: list, user_list: list):
    """
    Identify groups with no members by going through the
    :param group_list: List of the groups in the account
    :param user_list:  List of the active IAM users in the account
    :return: List of groups which have no active IAM users as members
    """
    empty_groups = copy.deepcopy(group_list)
    for user in user_list:
        for group in user['GroupList']:
            try:
                group_obj = next(g for g in empty_groups if g['GroupName'] == group)
                empty_groups.remove(group_obj)
            except StopIteration:
                pass

    return empty_groups


def find_unused_policy_attachments(users: list, roles: dict, account_policies: list, account_groups: list,
                                   unused_threshold) -> list:
    unused_policy_attachments = []
    for role in roles:
        unused_policy_attachments += get_unused_role_policy_attachments(account_policies, role)

    used_group_policy_attachments = []
    potential_unused_group_policy_attachments = []
    for user in users:
        services_in_use = list(map(lambda last_access: last_access['ServiceNamespace'],
                                   filter(lambda last_access: days_from_today(
                                       last_access['LastAccessed']) > 0 < unused_threshold, user['LastAccessed'])))
        user_attached_managed_policies = copy.deepcopy(user['AttachedManagedPolicies'])
        for group_name in user['GroupList']:
            group_managed_policies = next(
                g['AttachedManagedPolicies'] for g in account_groups if g['GroupName'] == group_name)
            user_attached_managed_policies.extend(
                list(map(lambda group_policy: {**group_policy, 'Group': group_name}, group_managed_policies)))

        for policy_attachment_obj in user_attached_managed_policies:
            policy_obj = next(p for p in account_policies if policy_attachment_obj['PolicyArn'] == p['Arn'])
            policy_document = \
            next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])['Document']
            policy_is_unused = PolicyAnalyzer.is_policy_unused(policy_document, services_in_use)
            if policy_attachment_obj.get('Group'):
                attachment_id = f'{policy_attachment_obj["PolicyName"]}/{policy_attachment_obj["Group"]}'
                if policy_is_unused:
                    potential_unused_group_policy_attachments.append({**policy_attachment_obj, 'id': attachment_id})
                else:
                    used_group_policy_attachments.append({**policy_attachment_obj, 'id': attachment_id})
            elif policy_is_unused:
                unused_policy_attachments.append({**policy_attachment_obj, 'User': user['UserName']})
    used_group_policy_attachments = {v['id']: v for v in used_group_policy_attachments}

    for policy_attachment_obj in potential_unused_group_policy_attachments:
        attachment_id = f'{policy_attachment_obj["PolicyName"]}/{policy_attachment_obj["Group"]}'
        if attachment_id not in used_group_policy_attachments:
            unused_policy_attachments.append(policy_attachment_obj)
            used_group_policy_attachments[attachment_id] = "Already added to 'unused_group_policy_attachments'"
    return unused_policy_attachments


def get_unused_role_policy_attachments(account_policies, principal):
    unused_policy_attachments = []
    if principal.get('LastAccessed') is None:
        return unused_policy_attachments
    services_last_accessed = list(map(lambda access_obj: access_obj['ServiceNamespace'], principal.get('LastAccessed')))
    for managed_policy in principal['AttachedManagedPolicies']:
        policy_obj = next(pol for pol in account_policies if pol['Arn'] == managed_policy['PolicyArn'])
        policy_document = next(version for version in policy_obj['PolicyVersionList'] if version['IsDefaultVersion'])[
            'Document']
        if PolicyAnalyzer.is_policy_unused(policy_document, services_last_accessed):
            unused_policy_attachments.append({"Role": principal['RoleName'], "PolicyArn": managed_policy['PolicyArn']})
    for inline_policy in principal.get('RolePolicyList', []):
        if PolicyAnalyzer.is_policy_unused(inline_policy['PolicyDocument'], services_last_accessed):
            unused_policy_attachments.append({"Role": principal['RoleName'], "PolicyArn": inline_policy['PolicyName']})

    return unused_policy_attachments


def days_from_today(str_date_from_today):
    if str_date_from_today in ['no_information', 'N/A']:
        return -1
    date = dt.datetime.fromisoformat(str_date_from_today)
    delta = dt.datetime.now().astimezone(timezone.utc) - date

    return delta.days
