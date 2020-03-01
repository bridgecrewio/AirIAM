from airiam.banner import banner

from colorama import init
from termcolor import colored

init(autoreset=True)


class Reporter:
    @staticmethod
    def report_cli(runtime_results, terraforming_results):
        print(colored(banner, 'yellow'))
        print('\nResults for Account {}:\n'.format(runtime_results['AccountId']))
        unused = runtime_results['Unused']
        unused_users = unused['UnusedUsers']
        if len(unused_users) > 0:
            print(colored('\nThe following {} users will be deleted:'.format(len(unused_users)), 'yellow', attrs=['bold']))
            for user in unused_users:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(user['UserName'], user['LastUsed']))

        unused_roles = unused['UnusedRoles']
        if len(unused_roles) > 0:
            print(colored('\nThe following {} roles will be deleted:'.format(len(unused_roles)), 'yellow', attrs=['bold']))
            for role in unused_roles:
                print(colored('Will be deleted: ', 'red', attrs=['bold']) + '{}: last used {} days ago'.format(role['RoleName'], role['LastUsed']))

        print('\n==================================================\n\n')
        print(colored('A terraform module was created with the following setup:', 'green'))
        user_org = runtime_results['Rightsizing']['UserOrganization']
        for admin in user_org['Admins']:
            print(colored('ADMIN: ', 'red', attrs=['bold']) + admin)
        for power_user in user_org['Powerusers']['Users']:
            print(colored('Power user: ', 'yellow', attrs=['bold']) + power_user)
        for user in user_org['ReadOnly']:
            print('Read Only: {}'.format(user))

        roles = runtime_results['Rightsizing']['RoleRightsizing']
        for role in roles:
            print('The role {} was copied as is to terraform'.format(role['Entity']['RoleName']))
