---
layout: default
published: true
title: Getting Started
order: 2
---

# Getting Started

The installation is quick and straightforward - install, configure input & scan.


```bash
# install from pypi using pip 
pip install airiam
```

## CLI Options
```bash
airiam --help

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Get AirIAM's version (default: False)

commands:
  {find_unused,recommend_groups,terraform}
    find_unused         Scan your runtime IAM for unused entities
    recommend_groups    Recommend IAM groups according to IAM users and their
                        in-use privileges
    terraform           Terraformize your runtime AWS IAM c

```

## Setup

### AWS Privileges required

#### AWS ROLE 
You must have AWS credentials configured that can be used by the CLI with read permissions for the different metadata to collect. I recommend using aws-vault. AirIAM will collect IAM information, which means you MUST use MFA. Only the collect step requires AWS access.
You must have the following privileges (these grant various read access of metadata):

`arn:aws:iam::aws:policy/SecurityAudit`

#### Credentials
AirIAM reads credentials from [profiles that is defined in file](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_profiles.html) `~/.aws/credentials` or using [credentials from environment variables](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_environment.html)

## Sample: Scan for unused entities (CLI)

Finding unused IAM entities:
```bash
airiam find_unused
For continuous scanning of your environment to detect drifts, connect to the Bridgecrew platform
Check us out - https://www.bridgecrew.cloud

INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Getting all IAM configurations for account 123456789123
Getting IAM credential report
Generated reports for all principals
Received usage results for all principals
Collecting password configurations for all IAM users in the account
Completed data collection, writing to local file...
Identifying unused IAM entities in the account...

The following 1 users were found to be unused:
Unused: jon@acme.io: last used 365 days ago

To delete these 1 users easily, utilize our scripts!

No unused access keys were found in the account! Hurray!

The following 2 users have password access they aren't using:
mike@acme.io has password access to the AWS console WITHOUT MFA but hasn't used it in the last [{'User': 'mike@acme.io', 'MFAEnabled': False, 'DaysSinceLastUse': 173}, {'User': 'jon@acme.io', 'MFAEnabled': False, 'DaysSinceLastUse': 365}] days
jon@acme.io has password access to the AWS console WITHOUT MFA but hasn't used it in the last [{'User': 'mike@acme.io', 'MFAEnabled': False, 'DaysSinceLastUse': 173}, {'User': 'jon@acme.io', 'MFAEnabled': False, 'DaysSinceLastUse': 365}] days


The following 195 roles are unused:
Unused: 123456789123-acme-analysis-lambda: last used 365 days ago
...
Unused: apidemo6-dev-us-west-2-lambdaRole: last used 127 days ago


Policy attached but not used: AmazonESCognitoAccessRole_democomp is not using the privileges given by arn:aws:iam::aws:policy/AmazonESCognitoAccess
Policy attached but not used: bc-acme-step-function-role-demo10 is not using the privileges given by step-function-execution-policy
...
Policy attached but not used: onelogin_admin is not using the privileges given by arn:aws:iam::aws:policy/AdministratorAccess

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

#TODO: OUTPUT SAMPLE


## Terraform result sample (CLI)
Rightsized IAM terraform templat generated:
#TODO OUTPUT SAMPLE
