import unittest

from airiam.main import parse_args


class TestAiriam(unittest.TestCase):
    def test_arg_parser_iam_default(self):
        args = parse_args(['iam'])
        self.assertEqual(args.command, 'iam')
        self.assertEqual(args.last_used_threshold, 90)
        self.assertFalse(args.list_unused)
        self.assertIsNone(args.profile)
        self.assertFalse(args.no_cache)

    def test_arg_parser_iam_custom(self):
        args = parse_args(['iam', '-p', 'dev', '--list-unused', '-l', '30', '--no-cache'])
        self.assertEqual(args.command, 'iam')
        self.assertEqual(args.last_used_threshold, 30)
        self.assertTrue(args.list_unused)
        self.assertEqual(args.profile, 'dev')
        self.assertTrue(args.no_cache)

    def test_arg_parser_terraform_default(self):
        args = parse_args(['tf'])
        self.assertEqual(args.command, 'tf')
        self.assertEqual(args.last_used_threshold, 90)
        self.assertFalse(args.without_unused)
        self.assertIsNone(args.profile)
        self.assertEqual(args.directory, 'results')
        self.assertFalse(args.no_cache)

    def test_arg_parser_terraform_custom(self):
        args = parse_args(['tf', '-p', 'dev', '--without-unused', '-l', '30', '--no-cache', '-d', 'tf_res'])
        self.assertEqual(args.command, 'tf')
        self.assertEqual(args.last_used_threshold, 30)
        self.assertTrue(args.without_unused)
        self.assertEqual(args.profile, 'dev')
        self.assertEqual(args.directory, 'tf_res')
        self.assertTrue(args.no_cache)
