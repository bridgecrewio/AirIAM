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

    def delete_policy(self, policy_arn):
        try:
            self._iam.delete_policy(PolicyArn=policy_arn)
            print(f'Deleted policy {policy_arn}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting policy: {error.response["Error"]["Message"]} - Skipping')

    def delete_role(self, role_name):
        # Detach policies
        more_results = True
        marker = None
        while more_results:
            if marker:
                res = self._iam.list_attached_role_policies(RoleName=role_name, Marker=marker)
            else:
                res = self._iam.list_attached_role_policies(RoleName=role_name)
            for policy in res['AttachedPolicies']:
                try:
                    self._iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                except botocore.exceptions.ClientError as error:
                    print(f'Error detaching role policy: {error.response["Error"]["Message"]} - Skipping')
            more_results = res.get('IsTruncated', False)
            if more_results:
                marker = res['Marker']

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

        # Remove from Instance Profiles
        more_results = True
        marker = None
        while more_results:
            if marker:
                res = self._iam.list_instance_profiles_for_role(RoleName=role_name, Marker=marker)
            else:
                res = self._iam.list_instance_profiles_for_role(RoleName=role_name)
            for instance_profile in res['InstanceProfiles']:
                try:
                    self._iam.remove_role_from_instance_profile(RoleName=role_name, InstanceProfileName=instance_profile['InstanceProfileName'])
                except botocore.exceptions.ClientError as error:
                    print(f'Error removing role from instance profile: {error.response["Error"]["Message"]} - Skipping')
            more_results = res.get('IsTruncated', False)
            if more_results:
                marker = res['Marker']

        # Delete the Role
        try:
            self._iam.delete_role(RoleName=role_name)
            print(f'Deleted role {role_name}')
        except botocore.exceptions.ClientError as error:
            print(f'Error deleting role: {error.response["Error"]["Message"]} - Skipping')
