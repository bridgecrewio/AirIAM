import json
import os
import unittest

from airiam.main import configure_logger
from airiam.models.RuntimeReport import RuntimeReport
from airiam.terraformer.TerraformTransformer import TerraformTransformer


class TestTerraformTransformer(unittest.TestCase):

    def test_terraformer_works(self):
        self.setup()
        report = RuntimeReport("012345678901", {'AccountGroups': [], 'AccountPolicies': [], 'AccountRoles': [], 'AccountUsers': []},
                               self.unused_users, self.unused_roles, self.unattached_policies, self.redundant_group, self.user_clusters,
                               self.roles_rightsizing)

        self.terraform_transformer.transform(report)
        self.assertTrue(os.path.exists('terraform/main.tf'))
        self.assertTrue(os.path.exists('terraform/developers.tf'))
        self.assertTrue(os.path.exists('terraform/power_users.tf'))
        self.assertTrue(os.path.exists('terraform/admins.tf'))
        self.assertTrue(os.path.exists('terraform/roles.tf'))

    def test_unused_not_in_terraform_code(self):
        self.setup()
        self.terraform_transformer.transform(RuntimeReport("012345678901", self.unused_users, self.unused_roles, self.unattached_policies,
                                                           self.redundant_group, self.user_clusters, self.special_users, self.roles_rightsizing))
        with open('terraform/roles.tf') as roles_file:
            roles = roles_file.read()

        self.assertFalse(f"resource \"aws_iam_role\" \"{self.unused_roles[0]['RoleName']}\"" in roles)

    def test_used_in_terraform_code(self):
        self.setup()
        self.terraform_transformer.transform(RuntimeReport("012345678901", self.unused_users, self.unused_roles, self.unattached_policies,
                                                           self.redundant_group, self.user_clusters, self.special_users, self.roles_rightsizing))
        with open('terraform/roles.tf') as roles_file:
            roles = roles_file.read()

        self.assertTrue(f"resource \"aws_iam_role\" \"{self.roles_rightsizing[0]['Entity']['RoleName']}\"" in roles)

        with open('terraform/main.tf') as main_file:
            main = main_file.read()
        self.assertTrue(json.dumps(self.user_clusters['Admins']) in main)
        self.assertTrue(json.dumps(self.user_clusters['Powerusers']['Policies']) in main)

    def setup(self):
        self.unused_users = [{"UserName": "Shati", "LastUsed": 198}]
        self.unused_roles = [{"RoleName": "hatulik-rules", "LastUsed": 330}]
        self.unattached_policies = []
        self.redundant_group = []
        self.user_clusters = {
            "Admins": ["wifi"],
            "Powerusers": {
                "Users": ["GanDalf"],
                "Policies": [
                    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
                    "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
                    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
                    "arn:aws:iam::aws:policy/AmazonESFullAccess"
                ]
            },
            "ReadOnly": ["kangaroo", "talm"]
        }
        self.special_users = []
        self.roles_rightsizing = [
            {
                "Entity": {
                    "RoleName": "ses-smtp-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole"]
                        }],
                        "Version": "2012-02-17",
                    },
                    "Path": '/'
                }
            }
        ]
        self.terraform_transformer = TerraformTransformer(configure_logger())
