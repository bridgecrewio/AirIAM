from colorama import init
from termcolor import colored

from airiam.models import RuntimeReport
from banner import banner
from version import version

SEPARATOR = '\n==================================================\n\n'

init(autoreset=True)


class Reporter:
    @staticmethod
    def report_runtime(list_unused: bool, runtime_results: RuntimeReport) -> None:
        if not list_unused:
            return

        unused = runtime_results.get_unused()
        unused_users = unused['Users']
        if len(unused_users) > 0:
            print(colored('\nThe following {} users are unused:'.format(len(unused_users)), 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Unused: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(user['UserName'], user['LastUsed']))

        unused_roles = unused['Roles']
        if len(unused_roles) > 0:
            print(colored('\nThe following {} roles are unused:'.format(len(unused_roles)), 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Unused: ', 'red', attrs=['bold']) + f"{role['RoleName']}: last used {role['LastUsed']} days ago")

        roles = runtime_results.get_rightsizing()['Roles']
        for role in roles:
            if len(role['policies_to_detach']) > 0:
                for policy in role['policies_to_detach']:
                    print(colored('Policy attached but not used: ', 'yellow', attrs=['bold']) +
                          f"Policy {policy['Policy']} attached to {role['role']['RoleName']}")

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
