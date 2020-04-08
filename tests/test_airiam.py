import unittest

from airiam.main import parse_args
from airiam.Reporter import OutputFormat


class TestAiriam(unittest.TestCase):
    def test_arg_parser_find_unused_default(self):
        args = parse_args(['find_unused'])
        self.assertEqual(args.command, 'find_unused')
        self.assertEqual(args.last_used_threshold, 90)
        self.assertIsNone(args.profile)
        self.assertFalse(args.no_cache)
        self.assertEqual(args.output, OutputFormat.cli)
        self.assertIsNone(args.ignore)

    def test_arg_parser_find_unused_custom(self):
        args = parse_args(['find_unused', '-p', 'dev', '-l', '30', '--no-cache', '-i', 'ignore.txt'])
        self.assertEqual(args.command, 'find_unused')
        self.assertEqual(args.last_used_threshold, 30)
        self.assertEqual(args.profile, 'dev')
        self.assertTrue(args.no_cache)
        self.assertEqual(args.ignore, 'ignore.txt')

    def test_arg_parser_recommend_groups_default(self):
        args = parse_args(['find_unused'])
        self.assertEqual(args.command, 'find_unused')
        self.assertEqual(args.last_used_threshold, 90)
        self.assertIsNone(args.profile)
        self.assertFalse(args.no_cache)
        self.assertEqual(args.output, OutputFormat.cli)
        self.assertIsNone(args.ignore)

    def test_arg_parser_recommend_groups_custom(self):
        args = parse_args(['find_unused', '-p', 'dev', '-l', '30', '--no-cache', '-i', 'ignore.txt'])
        self.assertEqual(args.command, 'find_unused')
        self.assertEqual(args.last_used_threshold, 30)
        self.assertEqual(args.profile, 'dev')
        self.assertTrue(args.no_cache)
        self.assertEqual(args.ignore, 'ignore.txt')

    def test_arg_parser_terraform_default(self):
        args = parse_args(['terraform'])
        self.assertEqual(args.command, 'terraform')
        self.assertEqual(args.last_used_threshold, 90)
        self.assertFalse(args.without_unused)
        self.assertIsNone(args.profile)
        self.assertEqual(args.directory, 'results')
        self.assertFalse(args.no_cache)
        self.assertIsNone(args.ignore)
        self.assertFalse(args.without_groups)

    def test_arg_parser_terraform_custom(self):
        args = parse_args(['terraform', '-p', 'dev', '--without-unused', '-l', '30', '--no-cache', '-d', 'tf_res', '-i', 'ignore.txt',
                           '--without-groups'])
        self.assertEqual(args.command, 'terraform')
        self.assertEqual(args.last_used_threshold, 30)
        self.assertTrue(args.without_unused)
        self.assertEqual(args.profile, 'dev')
        self.assertEqual(args.directory, 'tf_res')
        self.assertTrue(args.no_cache)
        self.assertEqual(args.ignore, 'ignore.txt')
        self.assertTrue(args.without_groups)
