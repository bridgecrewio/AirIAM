[![Maintained by Bridgecrew.io](https://img.shields.io/badge/maintained%20by-bridgecrew.io-blueviolet)](https://bridgecrew.io)
[![code_coverage](https://raw.githubusercontent.com/bridgecrewio/AirIAM/master/coverage.svg?sanitize=true)](https://github.com/bridgecrewio/AirIAM/actions?query=workflow%3Abuild-and-test)
![Terraform Version](https://img.shields.io/badge/tf-%3E%3D0.12.0-blue.svg)
![build](https://github.com/bridgecrewio/AirIAM/workflows/build-and-test/badge.svg)

# AirIAM
Automating, simplifying and least-privilege-ing complex existing AWS IAM resource mesh with terraform (IaC) 
> :construction: **WORK IN PROGRESS** :construction:

## **Table of contents**
- [Introduction](#introduction)
- [Commands](#commands)
- [Screenshots](#screenshots)
- [Getting Started](#getting-started)
- [Support](#support)


#### AirIAM is a tool that helps manage AWS IAM and migrate it to IaC.

<img src="https://www.syfy.com/sites/syfy/files/styles/2280x1280/public/2019/03/airiam_star_trek_disco1_header.jpg" width="400" />

> Airiam was a female cyberneticly enhanced Human serving as an officer in the Federation Starfleet in the 23rd century 
> until her death in 2257.

## Introduction
AirIAM scans existing IAM usage patterns and provides a simple method to migrate IAM configurations into a rightsized 
Terraform plan. It identifies unused users, roles, groups, policies and policy attachments and replaces them with a 
Least Privileges terraform code modeled accordingly.

By moving all configurations into Terraform code, users can start tracking, auditing and modifying IAM configurations 
as part of their standard infrastructure-as-code provisioning processes.

AirIAM is battle-tested and is recommended for use in Dev, QA and test environments that have been previously managed 
by humans. It is design to result in minimal affect on existing workloads. If you are interested in migrating a Prod 
account, contact us at info@bridgecrew.io or [open a ticket](https://bridgecrew.zendesk.com/hc/en-us/requests/new).

## Features

- Detects unused IAM resources using native AWS and [Amazon Access Advisor](https://aws.amazon.com/blogs/security/identify-unused-iam-roles-remove-confidently-last-used-timestamp/) APIs.
- Provide scripts to remove unused entities en-masse
- Effortless migration of existing IAM configurations into a simple Least Privileges IaC model. 
- Integrates with [Checkov](https://checkov.io) to track unwanted configuration changes and configuration drift.


## Commands
- `find_unused` - Uses AWS IAM APIs to detect unused users, roles, groups, policies and policy attachments.
- `remove_unused` - Uses the previous command, `find_unused`, to identify unused entities in the account
and adds links to scripts and automation which will help remove these entities in a quick and easy way. [Learn more 
about these scripts and automation](RecommendedAutomations.md).
- `recommend_groups` - Uses AWS IAM APIs to identify the different level of usages and create groups according to these
levels. Currently supported groups:
    - Admins - users which have the AdministratorAccess policy attached, will be added to the admins group which will 
    have the policy `arn:aws:iam::aws:policy/AdministratorAccess` attached
    - PowerUsers - users which have write access to **any** of the services they use will be added to the powerusers 
    group(s). In case of more than 10 policies being attached to that group, a number of groups will be created for 
    powerusers, and the relevant users will be members of all of them.
    - ReadOnly - users which only have read access to the account. Will be members of the readonly group which will have 
    the policy `arn:aws:iam::aws:policy/ReadOnlyAccess` attached 
- `terraform` - Creates Terraform files based on the configurations and the transformations applied by the optional
arguments supplied

## Screenshots

Report in CLI

***todo***

IAM migration plan

***todo***

## Getting started

### Installation

```sh
pip install airiam 
```

### Configuration

```sh
airiam -p <PROFILE> -u <NUM_OF_DAYS> -f <PATH_TO_DIR> -r
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
 
