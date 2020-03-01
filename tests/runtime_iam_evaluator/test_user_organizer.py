import os
import unittest
import json

from airiam.main import configure_logger
from airiam.runtime_iam_evaluator.UserOrganizer import UserOrganizer


class TestUserOrganizer(unittest.TestCase):
    def test_user_organizer(self):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        with open("{}/{}".format(current_dir, "../iam_data.json")) as f:
            iam_data = json.loads(json.load(f))
        unused_threshold = 90 + UserOrganizer.days_from_today('2020-02-17T11:41:00+00:00')
        logger = configure_logger()
        unused_users, human_users, simple_user_clusters, entities_to_detach = UserOrganizer(logger, unused_threshold).get_user_clusters(iam_data)
        self.assertEqual(len(simple_user_clusters), 3)
        self.assertEqual(len(unused_users), 14)
        self.assertTrue('Admins' in simple_user_clusters.keys())
        self.assertTrue('ReadOnly' in simple_user_clusters.keys())
        self.assertTrue('Powerusers' in simple_user_clusters.keys())
        self.assertEqual(len(simple_user_clusters.keys()), 3)
        self.assertEqual(len(simple_user_clusters['Admins']), 6)
        self.assertEqual(len(entities_to_detach), 479)
