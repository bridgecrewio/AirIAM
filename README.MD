[![Maintained by Bridgecrew.io](https://img.shields.io/badge/maintained%20by-bridgecrew.io-blueviolet)](https://bridgecrew.io)
[![code_coverage](https://raw.githubusercontent.com/bridgecrewio/AirIAM/master/coverage.svg?sanitize=true)](https://github.com/bridgecrewio/AirIAM/actions?query=workflow%3Abuild-and-test)
![Terraform Version](https://img.shields.io/badge/tf-%3E%3D0.12.0-blue.svg)
![build](https://github.com/bridgecrewio/AirIAM/workflows/build-and-test/badge.svg)

# AirIAM

AirIAM an AWS IAM least privileges to Terraform execution framework. It compiles AWS IAM usage and leverages that data to create a least-privilege IAM Terraform that replaces the exiting IAM management method.

AirIAM was created to promote immutable and version-controlled IAM management to replace today's manual and error prone methods.

## **Table of contents**

- [Introduction](#introduction)
- [Commands](#commands)
- [Run Configurations](#run-configurations)
- [Getting Started](#getting-started)
- [Support](#support)

## Introduction

AirIAM scans existing IAM usage patterns and provides a simple method to migrate IAM configurations into a rightsized 
Terraform plan. It identifies unused users, roles, groups, policies and policy attachments and replaces them with a 
Least Privileges Terraform code modeled to manage AWS IAM.

By moving all IAM configurations into Terraform code, admins can start tracking, auditing and modifying IAM configurations as part of their standard infrastructure-as-code development provisioning processes.

AirIAM is battle-tested and is recommended for use in Dev, QA and test environments that have been previously managed by humans. It is design to result in minimal impact on existing workloads. 

If you are interested in migrating a Prod account, contact us at info@bridgecrew.io for some helpful tips.

## Features

- Detects unused IAM resources using native AWS and [Amazon Access Advisor](https://aws.amazon.com/blogs/security/identify-unused-iam-roles-remove-confidently-last-used-timestamp/) APIs.
- Provides scripts to remove unused entities en-masse.
- Effortless migration of existing IAM configurations into a simple Least Privileges Terraform model. 
- Integrates with [Checkov](https://checkov.io), a static-code analysis tool for Terraform, to track unwanted configuration changes and configuration drift.


## Commands

- `find_unused` - Detects unused users, roles, groups, policies and policy attachments. It also adds links to automation scripts that could remove these entities entirely using Bridgecrew Community. [Learn more 
  about these scripts and automation](RecommendedIntegrations.md).
- `recommend_groups` - Identifies what permissions are in use and creates 3 generalized groups according to that usage. Supported groups:
    - Admins - Users who have the AdministratorAccess policy attached. It will be added to the admins group which will have the managed policy `arn:aws:iam::aws:policy/AdministratorAccess` attached.
    - PowerUsers - Users who have write access to **any** of the services. In case of more than 10 policies being attached to that group, a number of groups will be created for PowerUsers, and the relevant users will be members of all of them.
    - ReadOnly - Users who only have read access to the account. Will be members of the readonly group which will have the managed policy `arn:aws:iam::aws:policy/ReadOnlyAccess` attached.
- `terraform` - Creates Terraform files based on the outputs and the transformations applied by the optional arguments supplied.

### Usage Flow

The three commands above run sequentially, and in-sync, as seen in the diagram below.

When executing, AirIAM starts by scanning a selected AWS account using the specified profile. 
If `find_unused` is specified, the results are printed and the execution completes.
If `recommend_groups` is specified, after the stage of group recommendation the results are printed and the execution completes.
If the `terraform` command is specified it takes all the results and creates the Terraform code and state file required to replace the existing IAM configuration.

![Workflow](AirIAM%20Flow.svg)

## Getting Started

### Installation

```sh
pip install airiam 
```

### Run Configurations

#### General configurations for all commands

- `profile / p` defines which profile to use for AWS access. If none specified, the AWS credentials will be taken from 
  the default places (environment variables, default profile etc.)
- `last-unused-threshold / l` defines the threshold, in days, for entities to be marked as unused. Default value is 90
- `no-cache` defines whether to reuse local data or re-scan. If this is the first time or the account was changed from
  the last run, cache invalidation will occur anyway.

#### `find_unused`

- `output / o` defines the output format of the command. Default value is CLI.

#### `recommend_groups`

- `output / o` defines the output format of the command. Default value is CLI.

#### `terraform`

- `directory / d` defines the output directory for the terraform code. Default value is `results/`
- `ignore / i` defines a path to a text file listing regexp of entities which will be ignored by the terraform code 
  generator. 
- `--without-unused` defines unused should not be moved to terraform.

### Running the commands

```sh
airiam find_unused --profile dev --last-used-threshold 30 --no-cache

airiam recommend_groups --profile dev --last-used-threshold 90 --no-cache -o json

airiam terraform --profile dev --last-used-threshold 90 --no-cache --directory tf/iam -i ignore.txt --without-unused
```

## Alternatives

### AWS IAM Cleanup Tools 

For AWS IAM usage scanners check out [CloudTracker](https://github.com/duo-labs/cloudtracker), [Trailscraper](https://github.com/flosell/trailscraper/), 
[Aadvark](https://github.com/Netflix-Skunkworks/aardvark) & [Repokid](https://github.com/Netflix/repokid).
The main difference between these tools and AirIAM is that AirIAM also moves the problem into static terraform code form, which allows an entire set of code analysis tools to manage and identify deviations and changes.

### AWS IAM Policy Management Tools

For static IAM policy linting, check out [Parliament](https://github.com/duo-labs/parliament). Parliament is actually integrated into AirIAM, and is run on the policies it gets from your AWS account. 

For automatically creating IAM policies and managing them as code, check out  [aws-iam-generator](https://github.com/awslabs/aws-iam-generator),
[PolicySentry](https://github.com/salesforce/policy_sentry).

These tools help create better policies, but do not help with existing AWS IAM setup.

### Migration of AWS to terraform Tools

For other tools that help migrate existing AWS IAM setup to terraform, check out 
[terracognita](https://github.com/cycloidio/terracognita/) and [terraforming](https://github.com/dtan4/terraforming).
AirIAM is the only tool which supports migrating all relevant IAM entities to terraform v0.12.

## Contributing

Contribution is welcomed!

We would love to hear about other IAM governance models for additional use cases as well as new ways to identify over-permissive IAM resources. 

## Support

[Bridgecrew](https://bridgecrew.io) builds and maintains AirIAM to encourage the adoption of IAM-as-code and enforcement of IAM Rightsizing and Least Privileges best practices in policy-as-code. 

Start with our [Documentation](https://bridgecrewio.github.io/airiam/) for quick tutorials and examples.

If you need direct support you can contact us at info@bridgecrew.io or [open a ticket](https://bridgecrew.zendesk.com/hc/en-us/requests/new).
