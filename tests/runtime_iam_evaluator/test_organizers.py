import os
import unittest
import json

from airiam.main import configure_logger
from airiam.runtime_iam_evaluator.UserOrganizer import UserOrganizer
from airiam.runtime_iam_evaluator.RoleOrganizer import RoleOrganizer


class TestOrganizers(unittest.TestCase):
    def test_user_organizer(self):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        with open("{}/{}".format(current_dir, "../iam_data.json")) as f:
            iam_data = json.load(f)
        unused_threshold = 10 + UserOrganizer.days_from_today('2020-03-21T11:41:00+00:00')
        logger = configure_logger()
        unused_users, human_users, simple_user_clusters, entities_to_detach = UserOrganizer(logger, unused_threshold).get_user_clusters(iam_data)
        self.assertEqual(len(simple_user_clusters), 4)
        self.assertEqual(len(unused_users), 1)
        self.assertTrue('Admins' in simple_user_clusters.keys())
        self.assertTrue('ReadOnly' in simple_user_clusters.keys())
        self.assertTrue('Powerusers' in simple_user_clusters.keys())
        self.assertEqual(len(simple_user_clusters['UnchangedUsers']), 0, 'Expected to have 0 unchanged users')
        self.assertEqual(len(simple_user_clusters['Admins']), 2, 'Expected to have 2 admins')
        self.assertEqual(len(entities_to_detach), 5)

    def test_role_organizer(self):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        with open("{}/{}".format(current_dir, "../iam_data.json")) as f:
            iam_data = json.load(f)
            unused_threshold = 5 + UserOrganizer.days_from_today('2020-03-21T11:41:00+00:00')
            logger = configure_logger()
            unused_roles, rightsized = RoleOrganizer(logger).rightsize_privileges(iam_data['AccountRoles'], iam_data['AccountPolicies'],
                                                                                  iam_data['AccountGroups'])
        self.assertTrue(len(rightsized) == 7)
        self.assertTrue(len(unused_roles) == 1)
