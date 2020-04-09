import time
from enum import Enum

from colorama import init
from termcolor import colored

from airiam.banner import banner
from airiam.models import RuntimeReport
from airiam.version import version

SEPARATOR = '\n==================================================\n\n'

init(autoreset=True)


class OutputFormat(Enum):
    cli = 'CLI'


class Reporter:
    @staticmethod
    def report_unused(runtime_results: RuntimeReport) -> None:
        print(f'Identifying unused IAM entities in the account...\n')
        time.sleep(2)
        unused = runtime_results.get_unused()
        unused_users = unused['Users']
        if len(unused_users) > 0:
            print(colored(f'The following {len(unused_users)} users were found to be unused:', 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Unused: ', 'red', attrs=['bold']) + f'{user["UserName"]}: last used {user["LastUsed"]} days ago')
            print(f'\nTo delete these {len(unused_users)} users easily, utilize our scripts!')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_35/remediation/DeleteUser')
            time.sleep(5)
        else:
            print(colored('No unused users were found in the account! Hurray!', color='green'))

        print()
        unused_access_keys = unused['UnusedActiveAccessKeys']
        if len(unused_access_keys) > 0:
            print(colored(f'The following {len(unused_access_keys)} active access keys aren\'t being used:', 'yellow', attrs=['bold']))
            for access_key_obj in unused_access_keys:
                print(colored('Unused: ', 'red', attrs=['bold'])
                      + f'{access_key_obj["User"]} used access key #{access_key_obj["AccessKey"]} {access_key_obj["DaysSinceLastUse"]} days ago')
            print(f'\nTo disable these {len(unused_access_keys)} access keys easily, utilize our scripts!')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_4/remediation/IAMDisableUnusedCredentials')
            time.sleep(5)
        else:
            print(colored('No unused access keys were found in the account! Hurray!', color='green'))

        print()
        unused_console_login_profiles = unused['UnusedConsoleLoginProfiles']
        if len(unused_console_login_profiles) > 0:
            print(colored(f'The following {len(unused_console_login_profiles)} users have password access they aren\'t using:', 'yellow', attrs=['bold']))
            for console_login_profile in unused_console_login_profiles:
                has_mfa = console_login_profile['MFAEnabled']
                if has_mfa:
                    print(colored(console_login_profile['User'], 'yellow', attrs=['bold'])
                          + ' has password access to the AWS console (with MFA) but hasn\'t used it in the last '
                          + f'{console_login_profile["DaysSinceLastUse"]} days')
                else:
                    print(colored(console_login_profile['User'], 'red', attrs=['bold'])
                          + f' has password access to the AWS console ' + colored('WITHOUT MFA', 'red')
                          + f' but hasn\'t used it in the last {console_login_profile["DaysSinceLastUse"]} days')
            print(f'\nTo delete these {len(unused_console_login_profiles)} Console Login Profiles easily, utilize our scripts!:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_3/remediation/IAMDisableUserConsoleLogin')
            time.sleep(5)
        else:
            print(colored('No unused Console Login Profiles were found in the account! Hurray!', color='green'))

        print()
        unused_roles = unused['Roles']
        if len(unused_roles) > 0:
            print(colored(f'The following {len(unused_roles)} roles are unused:', 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Unused: ', 'red', attrs=['bold']) + f"{role['RoleName']}: last used {role['LastUsed']} days ago")
            print(f'\nTo delete these {len(unused_roles)} roles easily, utilize our scripts! A script which deletes a list of roles:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_34/remediation/DeleteRole')
            time.sleep(5)
        else:
            print(colored('No unused roles were found in the account! Hurray!', color='green'))

        print()
        unused_groups = unused['Groups']
        if len(unused_groups) > 0:
            print(colored(f'The following {len(unused_groups)} groups are redundant:', 'yellow', attrs=['bold']))
            for group in unused_groups:
                if len(group['AttachedManagedPolicies'] + group['GroupPolicyList']) == 0:
                    msg = ' has no policies attached to it'
                else:
                    msg = ' has no members'
                print(colored(group['GroupName'], 'yellow', attrs=['bold']) + msg)
            print(f'\nTo delete these {len(unused_groups)} groups easily, utilize our scripts!')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_38/remediation/DeleteEmptyGroup')
            time.sleep(5)
        else:
            print(colored('No redundant groups were found in the account! Hurray!', color='green'))

        print()
        unused_policies = unused['Policies']
        if len(unused_policies) > 0:
            print(colored(f'The following {len(unused_policies)} policies are redundant:', 'yellow', attrs=['bold']))
            for policy in unused_policies:
                print(colored(policy['PolicyName'], 'yellow', attrs=['bold']) + f' is not attached to any user, group or role')
            print(f'\nTo delete these {len(unused_policies)} policies easily, utilize our scripts!')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_39/remediation/DeletePolicy')
            time.sleep(5)
        else:
            print(colored('No unattached policies were found in the account! Hurray!', color='green'))

        print()
        unused_policy_attachments = unused['PolicyAttachments']
        if len(unused_policy_attachments) > 0:
            print(colored(f'The following {len(unused_policy_attachments)} policy attachments are unused:', 'yellow', attrs=['bold']))
            for policy_attachment in unused_policy_attachments:
                principal = policy_attachment.get('Role') or policy_attachment.get('User') or policy_attachment.get('Group')
                print(colored('Policy attached but not used: ', 'yellow', attrs=['bold']) + colored(principal, 'grey', attrs=['bold']) +
                      f' is not using the privileges given by {colored(policy_attachment["PolicyArn"], "red", attrs=["bold"])}')
            print(f'\nTo detach these policy attachments easily, utilize our scripts! A script which detaches policies from roles:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_41/remediation/DetachPolicyFromRole')
            time.sleep(5)
        else:
            print(colored('No unused policy attachments were found in the account! Hurray!', color='green'))

        print()
        print(SEPARATOR)

    @staticmethod
    def print_prelude():
        print(colored(banner, 'yellow'))
        print(f"""
For continuous scanning of your environment to detect drifts, connect to the {colored("Bridgecrew", 'magenta', attrs=['bold'])} platform
Check us out - https://www.bridgecrew.cloud
""")

    @staticmethod
    def report_groupings(report_with_recommendations: RuntimeReport):
        simple_user_clusters = report_with_recommendations.get_user_groups()
        admins = simple_user_clusters['Admins']
        read_only = simple_user_clusters['ReadOnly']
        powerusers = simple_user_clusters['Powerusers']
        print(colored(f'\nThe following {len(admins["Users"])} users require admin access to the account:', 'yellow', attrs=['bold']))
        for user in admins['Users']:
            print(colored('Admin: ', 'red', attrs=['bold']) + user)
        print()
        if len(powerusers['Users']) > 0:
            print(f'The following {len(powerusers["Users"])} users require ' +
                  colored('partial write', 'yellow', attrs=['bold']) +
                  ' access to the account:')
            for user in powerusers['Users']:
                print(colored('Poweruser: ', 'yellow', attrs=['bold']) + user)
        print()
        if len(read_only['Users']) > 0:
            print(colored(f'The following {len(read_only["Users"])} users require ReadOnly access to the account:', 'grey', attrs=['bold']))
            for user in read_only['Users']:
                print(colored('ReadOnly: ', 'green') + user)

        print(SEPARATOR)

    @staticmethod
    def report_terraform(terraform_results):
        print(SEPARATOR)

    @classmethod
    def print_version(cls):
        print(f"AirIAM version {version}")
