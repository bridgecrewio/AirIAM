from airiam.banner import banner
from airiam.models.RuntimeReport import RuntimeReport

from colorama import init
from termcolor import colored

SEPARATOR = '\n==================================================\n\n'

init(autoreset=True)


class Reporter:
    @staticmethod
    def report_runtime(runtime_results):
        """
        :param runtime_results: The results of the IAM scan
        :type runtime_results: RuntimeReport
        :return:
        """
        print('\nResults for Account {}:\n'.format(runtime_results.account_id))
        unused_users = runtime_results.unused_users
        if len(unused_users) > 0:
            print(colored('\nThe following {} users will be deleted:'.format(len(unused_users)), 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(user['UserName'], user['LastUsed']))

        unused_roles = runtime_results.unused_roles
        if len(unused_roles) > 0:
            print(colored('\nThe following {} roles will be deleted:'.format(len(unused_roles)), 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(role['RoleName'], role['LastUsed']))

        print(SEPARATOR)
        print(colored('A terraform module was created with the following setup:', 'green'))
        user_org = runtime_results.user_clusters
        for admin in user_org['Admins']:
            print(colored('ADMIN: ', 'red', attrs=['bold']) + admin)
        for power_user in user_org['Powerusers']['Users']:
            print(colored('Power user: ', 'yellow', attrs=['bold']) + power_user)
        for user in user_org['ReadOnly']:
            print('Read Only: {}'.format(user))
        for user in runtime_results.special_users:
            print(colored('Won\'t be changed: ', 'grey') + user['UserName'])

        roles = runtime_results.role_rightsizing
        for role in roles:
            print('The role {} was copied as is to terraform'.format(role['Entity']['RoleName']))

        print(SEPARATOR)

    @staticmethod
    def print_art():
        print(colored(banner, 'yellow'))

    @staticmethod
    def report_terraform(terraform_results):
        pass
