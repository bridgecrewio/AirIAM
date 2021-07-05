import json
import time

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

config = Config(retries={'max_attempts': 10, 'mode': 'standard'})


class Deleter:
    def __init__(self, profile=None):
        if profile:
            self._session = boto3.Session(profile_name=profile)
        else:
            self._session = boto3.Session()
        self._iam = self._session.client('iam', config=config)

    def _delete_inline_policies(self, resource_name, resource_type):
        resource_function_args_mapping = {
            'user': {
                'list_function' : 'list_user_policies',
                'detach_function': 'delete_user_policy',
                'arg_name': 'UserName',
            },
            'role': {
                'list_function': 'list_role_policies',
                'detach_function': 'delete_role_policy',
                'arg_name': 'RoleName'
            },
        }
        list_function = getattr(self._iam, resource_function_args_mapping[resource_type]['list_function'])
        detach_function = getattr(self._iam, resource_function_args_mapping[resource_type]['detach_function'])
        arg_name = resource_function_args_mapping[resource_type]['arg_name']
        kwargs = {arg_name: resource_name}

        # Delete Inline policies
        more_results = True
        marker = None
        while more_results:
            if marker:
                res = self._iam.list_role_policies(RoleName=role_name, Marker=marker)
            else:
                res = self._iam.list_role_policies(RoleName=role_name)
            for policy_name in res['PolicyNames']:
                try:
                    self._iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                except botocore.exceptions.ClientError as error:
                    print(f'Error deleting inline role policy: {error.response["Error"]["Message"]} - Skipping')
            more_results = res.get('IsTruncated', False)
            if more_results:
                marker = res['Marker']

    def _remove_all_attached(self, resource_name, resource_type):
        # Generic function to delete/detach resources related to a to-be-deleted target resource
        # e.g. for a user, delete all their MFA devices and Access Keys
        # Keeps us DRY when iterating through related items and taking some action on them (delete/detach/deactivate)

        # remove_function_specs is a hash containing, for each resource type
        # a list of functions and arguments we must use
        # in order to delete/detach all related items
        remove_function_specs = {
            'user': [
                {
                    # Attached Access Keys
                    'list_function_name': 'list_access_keys',
                    'list_kwargs': {'UserName': resource_name},
                    'list_data_items_key': 'AccessKeyMetadata',
                    'remove_function_name': 'delete_access_key',
                    'remove_kwargs': {'UserName': resource_name},
                    'remove_arg_name': 'AccessKeyId',
                },
                {
                    # Attached Policies
                    'list_function_name': 'list_attached_user_policies',
                    'list_kwargs': {'UserName': resource_name},
                    'list_data_items_key': 'AttachedPolicies',
                    'remove_function_name': 'detach_user_policy',
                    'remove_kwargs': {'UserName': resource_name},
                    'remove_arg_name': 'PolicyArn',
                },
                {
                    # Inline Policies
                    'list_function_name': 'list_user_policies',
                    'list_kwargs': {'UserName': resource_name},
                    'list_data_items_key': 'PolicyNames',
                    'remove_function_name': 'delete_user_policy',
                    'remove_kwargs': {'UserName': resource_name},
                    'remove_arg_name': 'PolicyName',
                },
                {
                    # MFA Devices
                    'list_function_name': 'list_mfa_devices',
                    'list_kwargs': {'UserName': resource_name},
                    'list_data_items_key': 'MFADevices',
                    'deactivate_function_name': 'deactivate_mfa_device',
                    'remove_function_name': 'delete_virtual_mfa_device',
                    'remove_kwargs': {},
                    'remove_arg_name': 'SerialNumber',
                },
            ],
            'role': [
                {
                    # Attached Policies
                    'list_function_name': 'list_attached_role_policies',
                    'list_kwargs': {'RoleName': resource_name},
                    'list_data_items_key': 'AttachedPolicies',
                    'remove_function_name': 'detach_role_policy',
                    'remove_kwargs': {'RoleName': resource_name},
                    'remove_arg_name': 'PolicyArn',
                },
                {
                    # Inline Policies
                    'list_function_name': 'list_role_policies',
                    'list_kwargs': {'RoleName': resource_name},
                    'list_data_items_key': 'PolicyNames',
                    'remove_function_name': 'delete_role_policy',
                    'remove_kwargs': {'RoleName': resource_name},
                    'remove_arg_name': 'PolicyName',
                },
                {
                    # Instance Profiles
                    'list_function_name': 'list_instance_profiles_for_role',
                    'list_kwargs': {'RoleName': resource_name},
                    'list_data_items_key': 'InstanceProfiles',
                    'remove_function_name': 'remove_role_from_instance_profile',
                    'remove_kwargs': {'RoleName': resource_name},
                    'remove_arg_name': 'InstanceProfileName',
                },
            ],
            'group': [
                {
                    # Attached Policies
                    'list_function_name': 'list_attached_group_policies',
                    'list_kwargs': {'GroupName': resource_name},
                    'list_data_items_key': 'AttachedPolicies',
                    'remove_function_name': 'detach_group_policy',
                    'remove_kwargs': {'GroupName': resource_name},
                    'remove_arg_name': 'PolicyArn',
                },
                {
                    # Inline Policies
                    'list_function_name': 'list_group_policies',
                    'list_kwargs': {'GroupName': resource_name},
                    'list_data_items_key': 'PolicyNames',
                    'remove_function_name': 'delete_group_policy',
                    'remove_kwargs': {'GroupName': resource_name},
                    'remove_arg_name': 'PolicyName',
                },
            ],
            'policy': [
                {
                    # Policy Versions
                    'list_function_name': 'list_policy_versions',
                    'list_kwargs': {'PolicyArn': resource_name},
                    'list_data_items_key': 'Versions',
                    'remove_function_name': 'delete_policy_version',
                    'remove_kwargs': {'PolicyArn': resource_name},
                    'remove_arg_name': 'VersionId',
                },
            ],
        }

        for function_spec in remove_function_specs[resource_type]:
            # list_function = getattr(self._iam, function_spec['list_function_name'])
            list_data_items_key = function_spec['list_data_items_key']
            remove_function = getattr(self._iam, function_spec['remove_function_name'])
            remove_arg_name = function_spec['remove_arg_name']
            deactivate_function = getattr(self._iam, function_spec.get('deactivate_function_name', ''), None)

            list_kwargs = function_spec['list_kwargs']
            pages = self._iam.get_paginator(function_spec['list_function_name']).paginate(**list_kwargs)
            for page in pages:
                list_items = page[list_data_items_key]
                for list_item in list_items:
                    # If the item has a value for remove_arg_name (e.g. PolicyArn) then grab that
                    # Otherwise
                    # (which is the case for list_role_policies, which returns only a list of strings, being PolicyNames)
                    # use the whole value itself (e.g. the PolicyName)
                    kwargs = function_spec['remove_kwargs'].copy()
                    try:
                        kwargs[remove_arg_name] = list_item[remove_arg_name]
                    except (KeyError, TypeError):
                        kwargs[remove_arg_name] = list_item

                    if deactivate_function:
                        try:
                            deactivate_function(**kwargs)
                        except botocore.exceptions.ClientError as error:
                            print(f'Error deactivating: {error.response["Error"]["Message"]} - Skipping')
                    try:
                        remove_function(**kwargs)
                    except botocore.exceptions.ClientError as error:
                        print(f'Error removing: {error.response["Error"]["Message"]} - Skipping')

    def detach_policy_from_principal(self, policy_attachment):
        if policy_attachment.get('User'):
            try:
                self._iam.delete_user_policy(UserName=policy_attachment.get('User'), PolicyName=policy_attachment['PolicyArn'])
                print(f"Deleted inline policy {policy_attachment['PolicyArn']}")
            except ClientError:
                try:
                    self._iam.detach_user_policy(UserName=policy_attachment.get('User'), PolicyArn=policy_attachment['PolicyArn'])
                    print(f"Detached policy {policy_attachment['PolicyArn']}")
                except ClientError:
                    print(f"Couldn't delete/detach policy {policy_attachment['PolicyArn']} from user {policy_attachment.get('User')} - Skipping")
        elif policy_attachment.get('Group'):
            try:
                self._iam.delete_group_policy(GroupName=policy_attachment.get('Group'), PolicyName=policy_attachment['PolicyArn'])
                print(f"Deleted inline policy {policy_attachment['PolicyArn']}")
            except ClientError:
                try:
                    self._iam.detach_group_policy(GroupName=policy_attachment.get('Group'), PolicyArn=policy_attachment['PolicyArn'])
                    print(f"Detached policy {policy_attachment['PolicyArn']}")
                except ClientError:
                    print(f"Couldn't delete/detach policy {policy_attachment['PolicyArn']} from user {policy_attachment.get('Group')} - Skipping")
        elif policy_attachment.get('Role'):
            try:
                self._iam.delete_role_policy(RoleName=policy_attachment.get('Role'), PolicyName=policy_attachment['PolicyArn'])
                print(f"Deleted inline policy {policy_attachment['PolicyArn']}")
            except ClientError:
                try:
                    self._iam.detach_role_policy(RoleName=policy_attachment.get('Role'), PolicyArn=policy_attachment['PolicyArn'])
                    print(f"Detached policy {policy_attachment['PolicyArn']}")
                except ClientError:
                    print(f"Couldn't delete/detach policy {policy_attachment['PolicyArn']} from user {policy_attachment.get('Role')} - Skipping")
        else:
            print(f"Don't know how to detach policy {policy_attachment['PolicyArn']} from principal {policy_attachment.get('User','') + policy_attachment.get('Group','') + policy_attachment.get('Policy','')} - Skipping")

    def delete_access_key(self, user_name, access_key_id):
        # Disable the access key
        try:
            self._iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Inactive')
        except botocore.exceptions.ClientError:
            # Don't care if it's already deactivated
            pass

        # Delete the access key
        try:
            self._iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            print(f'Deleted access key {access_key_id} for user {user_name}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting access key: {error.response["Error"]["Message"]} - Skipping')

    def delete_user(self, user_name):
        self._remove_all_attached(user_name, 'user')

        try:
            self._iam.delete_login_profile(UserName=user_name)
            print(f'Deleted login profile for {user_name}')
        except botocore.exceptions.ClientError as error:
            pass

        try:
            self._iam.delete_user(UserName=user_name)
            print(f'Deleted user {user_name}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting user: {error.response["Error"]["Message"]} - Skipping')

    def delete_policy(self, policy_arn):
        self._remove_all_attached(policy_arn, 'policy')

        try:
            self._iam.delete_policy(PolicyArn=policy_arn)
            print(f'Deleted policy {policy_arn}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting policy: {error.response["Error"]["Message"]} - Skipping')

    def delete_role(self, role_name):
        self._remove_all_attached(role_name, 'role')

        # Delete the Role
        try:
            self._iam.delete_role(RoleName=role_name)
            print(f'Deleted role {role_name}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting role: {error.response["Error"]["Message"]} - Skipping')

    def delete_group(self, group_name):
        self._remove_all_attached(group_name, 'group')

        # Delete the Role
        try:
            self._iam.delete_group(GroupName=group_name)
            print(f'Deleted group {group_name}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting group: {error.response["Error"]["Message"]} - Skipping')
