[![Maintained by Bridgecrew.io](https://img.shields.io/badge/maintained%20by-bridgecrew.io-blueviolet)](https://bridgecrew.io)
[![code_coverage](https://raw.githubusercontent.com/bridgecrewio/AirIAM/master/coverage.svg?sanitize=true)](https://github.com/bridgecrewio/AirIAM/actions?query=workflow%3Abuild-and-test)
![Terraform Version](https://img.shields.io/badge/tf-%3E%3D0.12.0-blue.svg)
![build](https://github.com/bridgecrewio/AirIAM/workflows/build-and-test/badge.svg)

# AirIAM
Automating, simplifying and least-privilege-ing complex existing AWS IAM resource mesh with terraform (IaC) 
> :construction: **WORK IN PROGRESS** :construction:

![Airiam](https://www.syfy.com/sites/syfy/files/styles/2280x1280/public/2019/03/airiam_star_trek_disco1_header.jpg)
> Airiam was a female cyberneticly enhanced Human serving as an officer in the Federation Starfleet in the 23rd century 
> until her death in 2257.

AirIAM migrates an existing account's AWS IAM configurations into terraform, allowing easier access 
management, enabling review process and rolling back bad configurations easily.
While at it, AirIAM also reduces unused permissions to make sure the environment is adherent
to the least-privilege principal.

 
 # Step 1 - Organizing employee's IAM users
 AirIAM identifies human users as users which used the console login. This means these IAM users both have a console 
 login profile **and** they used it to login to the console.
 It creates 3 different groups for these users:
 1. Admin group - for admin users.
 2. Powerusers group - users which are constantly accessing a closed set of write permissions.
 3. ReadOnly group - everyone else.
 
 In the output the powerusers group is empty, and users which are not admins will need to be manually elevated
 to the powerusers group.
 
 ## **Table of contents**

- [Description](#description)
- [Features](#features)
- [Screenshots](#screenshots)
- [Getting Started](#getting-started)
- [Support](#support)

## Description

AirIAM scans existing IAM usage patterns and provides a simple method to migrate IAM configurations into a rightsized Terraform plan. It removes unused users and groups and replaces them with a Least Privileges model consisting of three groups: `admins`, `powerusers`, `read-only` . 

By moving all configurations into Terraform code, users can start tracking, auditing and modifying IAM configurations as part of their standard infrastructure-as-code provisioning processes.

AirIAM is battle-tested and is recommended for use in Dev, QA and test environments that have been previously managed by humans. It is design to result in minimal affect on existing workloads. If you are interested in migrating a Prod account, contact us at info@bridgecrew.io or [open a ticket](https://bridgecrew.zendesk.com/hc/en-us/requests/new).

 ## Features

 * Effortless migration of existing IAM configurations into a simple Least Privileges model. 
 * Generates a Terraform plan for migration AND rollback.
 * Detects unused IAM resources using native [Amazon Access Advisor](https://aws.amazon.com/blogs/security/identify-unused-iam-roles-remove-confidently-last-used-timestamp/) APIs.
 * Integrates with [Checkov](https://checkov.io) to track unwanted configuration changes and configuration drift.

## Screenshots

Report in CLI

***todo***

IAM migration plan

***todo***

## Getting started

### Installation

```sh
git clone https://github.com/bridgecrewio/AirIAM.git
cd AirIAM/
pipenv install --skip-lock
pipenv shell
```

### Configuration

```sh
python airiam.py -p <PROFILE> -u <NUM_OF_DAYS> -f <PATH_TO_DIR> -r
```

`profile / p` will use your custom profile and perform the initial checks over all regions when needed.

`unused / u` will define how many days will be considered as a least-usage threshold. By default value is 90, meaning, that any resource that was not active in the last 90 will be identified as unused and removed from the Terraform plan.

`folder / f` will define where the execution recovery plan and state files will be stored. By default, the files will be placed in a `results` folder.

`rightsize / r` will define whether to rightsize the permissions automatically using usage data from AWS or not.

### Report

```sh
***todo***
```

The execution report is a JSON file containing the following data models used to build the Terraform execution files.

1. Raw data: all AWS API data collected to perform the analysis. 
2. Unused data: users, groups, roles and permissions and their last-seen parameters.
3. Rightsized result: active user and groups mapped into a simplified governance model (admins, super-users, read-only)

### Implementation

***todo***

## Alternatives ***todo***

For IAM rightsizing scanners check out [CloudTracker](https://github.com/duo-labs/cloudtracker), [Trailscraper](https://github.com/flosell/trailscraper/) [Aadvark](https://github.com/Netflix-Skunkworks/aardvark) and [Parliament](https://github.com/duo-labs/parliament).

For IAM Terraform migration projects check out [aws-iam-generator](https://github.com/awslabs/aws-iam-generator),[tf-parliament](https://github.com/rdkls/tf-parliament). 

## Contributing

Contribution is welcomed!

We would love to hear about other IAM governance models for additional use cases as well as new ways to identify over-permissive IAM resources. 

## Support

[Bridgecrew](https://bridgecrew.io) builds and maintains AirIAM to encourage the adoption of IAM-as-code and enforcement of IAM Rightsizing and Least Privileges best practices in policy-as-code. 

Start with our [Documentation](https://bridgecrewio.github.io/airiam/) for quick tutorials and examples.

If you need direct support you can contact us at info@bridgecrew.io or [open a ticket](https://bridgecrew.zendesk.com/hc/en-us/requests/new).
 
