import json
import os
import unittest

from airiam.main import configure_logger
from airiam.models.RuntimeReport import RuntimeReport
from airiam.terraformer.TerraformTransformer import TerraformTransformer


class TestTerraformTransformer(unittest.TestCase):

    def test_terraformer_works(self):
        self.setup()
        self.terraform_transformer.transform(self.report, should_import=False)
        self.assertTrue(os.path.exists('main.tf'), 'Did not create a main file')
        self.assertTrue(os.path.exists('users.tf'), 'Did not create a users file')
        self.assertTrue(os.path.exists('policies.tf'), 'Did not create a policies file')

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
        self.report = RuntimeReport("012345678901", {'AccountGroups': [], 'AccountPolicies': [], 'AccountRoles': [], 'AccountUsers': []},
                                    self.unused_users, self.unused_roles, self.unattached_policies, self.redundant_group, self.user_clusters,
                                    self.roles_rightsizing)
