from banner import banner
from models.RuntimeReport import RuntimeReport

from colorama import init
from termcolor import colored

SEPARATOR = '\n==================================================\n\n'

init(autoreset=True)


class Reporter:
    @staticmethod
    def report_runtime(rightsize: bool, runtime_results: RuntimeReport) -> None:
        if not rightsize:
            print('No rightsizing selected, creating terraform code for IAM runtime as is')
            return

        print('\nResults for Account {}:\n'.format(runtime_results.account_id))
        unused = runtime_results.get_unused()
        unused_users = unused['Users']
        if len(unused_users) > 0:
            print(colored('\nThe following {} users will be deleted:'.format(len(unused_users)), 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(user['UserName'], user['LastUsed']))

        unused_roles = unused['Roles']
        if len(unused_roles) > 0:
            print(colored('\nThe following {} roles will be deleted:'.format(len(unused_roles)), 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(role['RoleName'], role['LastUsed']))

        print(SEPARATOR)
        print(colored('A terraform module was created with the following setup:', 'green'))
        user_org = runtime_results.get_rightsizing()['Users']
        for admin in user_org['Admins']:
            print(colored('ADMIN: ', 'red', attrs=['bold']) + admin)
        for power_user in user_org['Powerusers']['Users']:
            print(colored('Power user: ', 'yellow', attrs=['bold']) + power_user)
        for user in user_org['ReadOnly']:
            print('Read Only: {}'.format(user))
        for user in user_org['UnchangedUsers']:
            print(colored('Won\'t be changed: ', 'grey') + user['UserName'])

        roles = runtime_results.get_rightsizing()['Roles']
        for role in roles:
            if len(role['policies_to_detach']) > 0:
                print(colored('The role {} will have reduced permissions'.format(role['role']['RoleName']), 'yellow'))
            else:
                print('The role {} was copied as is to terraform'.format(role['role']['RoleName']))

        print(SEPARATOR)

    @staticmethod
    def print_prelude():
        print(colored(banner, 'yellow'))
        print(f"""
For continuous scanning of your environment to detect drifts, connect to the {colored("FREE", 'green', attrs=['bold'])} {colored("Bridgecrew", 'magenta', attrs=['bold'])} platform
Check us out!
https://www.bridgecrew.cloud
https://www.bridgecrew.io
""")

    @staticmethod
    def report_terraform(terraform_results):
        pass
