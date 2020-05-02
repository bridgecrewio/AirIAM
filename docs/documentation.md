# Airiam Documentation

AirIAM is a tool to identify and automate Least privilege IAM principles in AWS using Terraform. 

AirIAM is written in Python and aims to simplify and increase the adoption of infrastructure code for IAM management. 

See how to [install and get AirIAM up and running](#getting-started).
Next [learn how to find unused IAM policies](#sample-scan-for-unused-entities-cli). 
After that, [learn how to group your users intelligently](#sample-recommend-iam-grouping-cli).
Finally, [learn how to migrate your setup to terraform](#sample-terraform-results-sample-cli).

After you're familiar with the tool, check out the [recommended workflow](#recommended-workflow)

![](web/images/airiam-recording.gif)


## Getting Started

The installation is quick and straightforward - install, configure input & scan.


```
# install from pypi using pip 
$ pip install airiam
```

## CLI Options

```
$  airiam -h
     ____      __           _____      ____     __        __
    / __ \    |__|  _  ____|_   _|    / __ \   |   \    /   |
   / /  \ \    __  | |/ ___| | |     / /  \ \  | |\ \  / /| |
  / /____\ \  |  | |   /     | |    / /____\ \ | | \ \/ / | |
 /  ______  \_|  |_|  |     _| |_  /  ______  \  |  \  /  | |
/_/        \_\_____|__|    |_____|/_/        \_\_|   \/   |_|
v0.1.22 

AirIAM - Least privilege AWS IAM Terraformer

To continuously scan configurations, try the Bridgecrew free community plan.
https://www.bridgecrew.io

usage: airiam [-h] [-v] {find_unused,recommend_groups,terraform} ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Get AirIAM's version (default: False)

commands:
  {find_unused,recommend_groups,terraform}
    find_unused         Scan your runtime IAM for unused entities
    recommend_groups    Recommend IAM groups according to IAM users and their
                        in-use privileges
    terraform           Terraformize your runtime AWS IAM configurations
```

## Setup

### AWS Privileges required

#### AWS ROLE 
You must have AWS credentials configured that can be used by the CLI with read permissions for IAM. I recommend using aws-vault. AirIAM will collect IAM information.
The privileges that are required can be attained using either 

#### Credentials
AirIAM reads credentials from [profiles that is defined in file](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_profiles.html) `~/.aws/credentials` or using [credentials from environment variables](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_environment.html)

## Sample: Scan for unused entities (CLI)

Finding unused IAM entities:

```
$ airiam find_unused
     ____      __           _____      ____     __        __
    / __ \    |__|  _  ____|_   _|    / __ \   |   \    /   |
   / /  \ \    __  | |/ ___| | |     / /  \ \  | |\ \  / /| |
  / /____\ \  |  | |   /     | |    / /____\ \ | | \ \/ / | |
 /  ______  \_|  |_|  |     _| |_  /  ______  \  |  \  /  | |
/_/        \_\_____|__|    |_____|/_/        \_\_|   \/   |_|
v0.1.22 

AirIAM - Least privilege AWS IAM Terraformer

To continuously scan configurations, try the Bridgecrew free community plan.
https://www.bridgecrew.io

INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Reusing local data
Identifying unused IAM entities in the account...

The following 4 users were found to be unused:
Unused: misconfigured-admin-user: last used 365 days ago
Unused: s3-user2: last used 365 days ago
Unused: unused-admin-user: last used 365 days ago
Unused: unused-user: last used 365 days ago

No unused access keys were found in the account! Hurray!

No unused Console Login Profiles were found in the account! Hurray!

The following 3 roles are unused:
Unused: do-nothing-function-role-f9tyradi: last used 365 days ago
Unused: OrganizationAccountAccessRole: last used 365 days ago
Unused: serverless-architecture-admin: last used 365 days ago

The following 2 groups are redundant:
group-without-memebers has no members
group-without-policies has no policies attached to it

The following 1 policies are redundant:
unattached-policy is not attached to any user, group or role

The following 1 policy attachments are unused:
Policy attached but not used: s3-user1 is not using the privileges given by arn:aws:iam::000000000000:policy/sts-policy

If you prefer to to change the current runtime and not move to IaC but the number of entities above is intimidating - consider using our playbooks, available at: 
https://www.bridgecrew.io/

```

## Sample: Recommend IAM grouping (CLI)
> By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are
  the means by which privileges are granted to users, groups, or roles. It is recommended
  that IAM policies be applied directly to groups and roles but not users
  
> **Rationale:**
  Assigning privileges at the group or role level reduces the complexity of access
  management as the number of users grow. Reducing access management complexity may
  in-turn reduce opportunity for a principal to inadvertently receive or retain excessive
  privileges
  > > [CIS AWS Foundations](https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) - "1.16 Ensure IAM policies are attached only to groups or roles (Scored)"

Recommending groups output example:

```
$  airiam recommend_groups
     ____      __           _____      ____     __        __
    / __ \    |__|  _  ____|_   _|    / __ \   |   \    /   |
   / /  \ \    __  | |/ ___| | |     / /  \ \  | |\ \  / /| |
  / /____\ \  |  | |   /     | |    / /____\ \ | | \ \/ / | |
 /  ______  \_|  |_|  |     _| |_  /  ______  \  |  \  /  | |
/_/        \_\_____|__|    |_____|/_/        \_\_|   \/   |_|
v0.1.22 

AirIAM - Least privilege AWS IAM Terraformer

To continuously scan configurations, try the Bridgecrew free community plan.
https://www.bridgecrew.io

INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Reusing local data
INFO:root:Analyzing data for account 000000000000
INFO:root:Using the default UserOrganizer

The following 1 users require admin access to the account:
Admin: nimrod

The following 1 users require partial write access to the account:
Poweruser: s3-user1
```

## Sample: Terraform results sample (CLI)
Example `terraform` output:

```
$ airiam terraform                 
     ____      __           _____      ____     __        __
    / __ \    |__|  _  ____|_   _|    / __ \   |   \    /   |
   / /  \ \    __  | |/ ___| | |     / /  \ \  | |\ \  / /| |
  / /____\ \  |  | |   /     | |    / /____\ \ | | \ \/ / | |
 /  ______  \_|  |_|  |     _| |_  /  ______  \  |  \  /  | |
/_/        \_\_____|__|    |_____|/_/        \_\_|   \/   |_|
v0.1.22 

AirIAM - Least privilege AWS IAM Terraformer

To continuously scan configurations, try the Bridgecrew free community plan.
https://www.bridgecrew.io

INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Reusing local data
Filtered arn:aws:iam::000000000000:user/nimrod from the analysis
INFO:root:Analyzing data for account 000000000000
INFO:root:Using the default UserOrganizer
Importing 53 entities
Imported all existing entities to state
Successfully migrated your current IAM setup to terraform!
Migrated 6 users, 4 groups, 4 roles and 18 policies, as well as all connections between them, to terraform.
Your terraform files can now be found at the directory you specified: results
```

By default, the resulting terraform template will be stored in a folder called `results`. The directory structure:

results  
|─ groups.tf  
|─ main.tf  
|─ policies.tf  
|─ roles.tf  
|─ terraform.tfstate  
└─ users.tf

## Recommended Workflow
The recommended workflow for using this tool is as follows:
1. Run the `find_unused` command and delete the unused access keys + unused console logins - these cannot be migrated 
to terraform because they hold secrets known only to the relevant user - his password and private credentials.
2. Run the `terraform` command without any flags, creating a terraform setup that mirrors your existing IAM setup. This will take a while as all of the entities will be imported to your state file
3. Commit the terraform files (**without the state file**) to a new repository.
4. Run the `terraform` command again, this time with the flag `--without-import` and `--without-unused`. This will edit the `.tf` files to contain only the entities that are in use.
5. Create a new branch and commit the new terraform files.
6. Create a Pull Request / Merge Request from this branch to the default branch. Check out the differences and make sure all the changes are good. Consult relevant stakeholders in your organization if necessary.
7. After approval - merge the PR and apply the changes using `terraform apply`. Please note this action will require **Admin** IAM access to the account.
