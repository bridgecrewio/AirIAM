from python_terraform import *

from airiam.models.RuntimeReport import RuntimeReport
from airiam.terraformer.entity_terraformers.AWSProviderTransformer import AWSProviderTransformer
from airiam.terraformer.entity_terraformers.IAMPolicyTransformer import IAMPolicyTransformer
from airiam.terraformer.entity_terraformers.IAMUserTransformer import IAMUserTransformer

current_dir = os.path.abspath(os.path.dirname(__file__))
boilerplate_files = ["admins.tf", "developers.tf", "power_users.tf"]


class TerraformTransformer:
    def __init__(self, logger, profile=None):
        self.logger = logger
        self.profile = profile

    def transform(self, results, should_import=True):
        """
        Creates terraform files from the setup it receives
        :param results: IAM scan results
        :type results: RuntimeReport
        :param should_import: For testing only
        :return:
        """
        with open('main.tf', 'w') as main_file:
            main_code = AWSProviderTransformer({'region': 'us-east-1', 'profile': self.profile}).code()
            main_file.write(main_code)
        with open('policies.tf', 'w') as policies_file:
            policy_code = ""
            for policy in results.get_raw_data()['AccountPolicies']:
                policy_code += IAMPolicyTransformer(policy).code()
            policies_file.write(policy_code)

        with open('users.tf', 'w') as users_file:
            user_code = ""
            for user in results.get_raw_data()['AccountUsers']:
                user_code += IAMUserTransformer(user).code()
            users_file.write(user_code)
        if should_import:
            tf = Terraform()
            tf.init(backend=False)
            for user in results.get_raw_data()['AccountUsers']:
                print(f"Importing {user['UserName']}")
                tf.import_cmd(f"aws_iam_user.{IAMUserTransformer.safe_name_converter(user['UserName'])}", user['UserName'])
        return "Success"
