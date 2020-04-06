from colorama import init
from enum import Enum
from termcolor import colored
import time

from airiam.models import RuntimeReport
from airiam.banner import banner
from airiam.version import version

SEPARATOR = '\n==================================================\n\n'

init(autoreset=True)


class OutputFormat(Enum):
    cli = 'CLI'


class Reporter:
    @staticmethod
    def report_unused(runtime_results: RuntimeReport) -> None:
        print(f'Identifying unused {colored("users", color="yellow", attrs=["bold"])}, {colored("roles", color="green", attrs=["bold"])} and '
              f'{colored("unused police attachments", color="grey", attrs=["bold"])}')
        time.sleep(2)
        unused = runtime_results.get_unused()
        unused_users = unused['Users']
        if len(unused_users) > 0:
            print(colored(f'\nThe following {len(unused_users)} users were found to be unused:', 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Unused: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(user['UserName'], user['LastUsed']))
            print(f'\nTo delete these {len(unused_users)} users easily, utilize our scripts! A script which deletes a list of users:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_35/remediation/DeleteUser')
            time.sleep(5)
        else:
            print(colored('No unused users found in the account! Hurray!', color='green'))
        unused_roles = unused['Roles']
        if len(unused_roles) > 0:
            print(colored('\nThe following {} roles are unused:'.format(len(unused_roles)), 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Unused: ', 'red', attrs=['bold']) + f"{role['RoleName']}: last used {role['LastUsed']} days ago")
            print(f'\nTo delete these {len(unused_roles)} roles easily, utilize our scripts! A script which deletes a list of roles:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_34/remediation/DeleteRole')
            time.sleep(5)

        print()
        unused_policy_attachments = unused['PolicyAttachments']
        print_playbook = len(unused_policy_attachments) > 0
        for policy_attachment in unused_policy_attachments:
            principal = policy_attachment.get('Role') or policy_attachment.get('User') or policy_attachment.get('Group')
            print(colored('Policy attached but not used: ', 'yellow', attrs=['bold']) + colored(principal, 'grey', attrs=['bold']) +
                  f' is not using the privileges given by {colored(policy_attachment["PolicyArn"], "red", attrs=["bold"])}')
        if print_playbook:
            print(f'\nTo detach these policy attachments easily, utilize our scripts! A script which detaches policies from roles:')
            print('https://www.bridgecrew.cloud/incidents/BC_AWS_IAM_41/remediation/DetachPolicyFromRole')
            time.sleep(5)

        print(SEPARATOR)

    @staticmethod
    def print_prelude():
        print(colored(banner, 'yellow'))
        print(f"""
For continuous scanning of your environment to detect drifts, connect to the {colored("Bridgecrew", 'magenta', attrs=['bold'])} platform
Check us out - https://www.bridgecrew.cloud
""")

    @staticmethod
    def report_terraform(terraform_results):
        print(SEPARATOR)

        print(colored('A terraform module was created with the following setup:', 'green'))
        user_org = terraform_results.get_rightsizing()['Users']
        for admin in user_org['Admins']:
            print(colored('ADMIN: ', 'red', attrs=['bold']) + admin)
        for power_user in user_org['Powerusers']['Users']:
            print(colored('Power user: ', 'yellow', attrs=['bold']) + power_user)
        for user in user_org['ReadOnly']:
            print('Read Only: {}'.format(user))
        for user in user_org['UnchangedUsers']:
            print(colored('Won\'t be changed: ', 'grey') + user['UserName'])

    print(SEPARATOR)

    @classmethod
    def print_version(cls):
        print(f"AirIAM version {version}")
