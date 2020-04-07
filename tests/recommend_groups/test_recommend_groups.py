import json
import os
import unittest

from airiam.find_unused.find_unused import *
from airiam.main import configure_logger
from airiam.models.RuntimeReport import RuntimeReport
from airiam.recommend_groups.recommend_groups import UserOrganizer
from airiam.Reporter import Reporter


class TestOrganizers(unittest.TestCase):

    def test_user_organizer(self):
        unused_threshold = 10 + days_from_today('2020-03-21T11:41:00+00:00')
        current_dir = os.path.abspath(os.path.dirname(__file__))
        with open("{}/{}".format(current_dir, "../iam_data.json")) as f:
            iam_data = json.load(f)
        self.report = RuntimeReport('000000000000', iam_data)
        credential_report = iam_data['CredentialReport']
        account_users = iam_data['AccountUsers']
        account_roles = iam_data['AccountRoles']
        account_policies = iam_data['AccountPolicies']
        account_groups = iam_data['AccountGroups']
        unused_users, used_users = find_unused_users(account_users, credential_report, unused_threshold)
        unused_active_access_keys, unused_console_login_profiles = find_unused_active_credentials(account_users, credential_report, unused_threshold)
        unattached_policies = find_unattached_policies(account_policies)
        redundant_groups = find_redundant_groups(account_groups, account_users)
        unused_roles, used_roles = find_unused_roles(account_roles, unused_threshold)
        unused_policy_attachments = find_unused_policy_attachments(account_users, account_roles, account_policies, account_groups, unused_threshold)
        unused_policy_attachments = filter_attachments_of_unused_entities(unused_policy_attachments, unused_users, unused_roles, redundant_groups)
        self.report.set_unused(unused_users, unused_roles, unused_active_access_keys, unused_console_login_profiles, unattached_policies,
                               redundant_groups, unused_policy_attachments)

        self.user_organizer = UserOrganizer(configure_logger(), unused_threshold)
        simple_user_clusters = self.user_organizer.get_user_clusters(self.report)
        self.assertEqual(len(simple_user_clusters), 4)
        self.assertEqual(len(unused_users), 1)
        self.assertTrue('Admins' in simple_user_clusters.keys())
        self.assertTrue('ReadOnly' in simple_user_clusters.keys())
        self.assertTrue('Powerusers' in simple_user_clusters.keys())
        self.assertEqual(len(simple_user_clusters['UnchangedUsers']), 0, 'Expected to have 0 unchanged users')
        self.assertEqual(len(simple_user_clusters['Admins']), 2, 'Expected to have 2 admins')
        self.report.set_reorg(simple_user_clusters)
        Reporter.report_groupings(self.report)


if __name__ == '__main__':
    unittest.main()
