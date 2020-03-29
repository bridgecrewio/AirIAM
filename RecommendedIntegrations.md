# Recommended Integrations
Recommended integrations with AirIAM:
1. [Bridgecrew Cloud](#integration-with-bridgecrew-cloudhttpswwwbridgecrewcloud)
2. [Checkov](#integration-with-checkov)

## Integration with [Bridgecrew cloud](https://www.bridgecrew.cloud)
To remove entities en-masse in a simple-to-use, time-efficient manner, we recommend utilizing the free community version
of `Bridgecrew`'s platform, [Bridgecrew Cloud](https://www.bridgecrew.cloud).

The setup will contain 3 steps:
1. [Configuring a new customer with Bridgecrew](#configuring-a-new-customer-with-bridgecrew)
2. [Granting Bridgecrew READ ONLY access to your AWS account](#granting-bridgecrew-read-only-access)
3. [Finding the relevant automations](#finding-the-relevant-automations)

### Configuring a new customer with Bridgecrew
To configure a new customer with `Bridgecrew`, simply go to [Bridgecrew Cloud](https://www.bridgecrew.cloud) and use one
of the signup methods to create a new user - Google, Github and regular email-based authentication is supported.

### Granting Bridgecrew READ ONLY access
To grant `Bridgecrew` access to your account it is required to deploy a [CloudFormation stack](#deploying-using-cloudformation)
 / [terraform module](#deploying-using-terraform) in the 
target account.

#### Deploying using CloudFormation
To deploy using CloudFormation: 
1. Log into your AWS account. No need to keep that tab open.
2. Log into [Bridgecrew Cloud](https://www.bridgecrew.cloud)
3. Go to `Integrations` tab, select the `AWS Read Access` integration
4. Click `ADD ACCOUNT` and then `LAUNCH STACK` 

#### Deploying using Terraform
To deploy using Terraform, import [our module](https://registry.terraform.io/modules/bridgecrewio/bridgecrew-read-only/)
 from the terraform registry and insert the relevant parameters:
 ```hcl-terraform
module "bridgecrew-read-only" {
  source        = "bridgecrewio/bridgecrew-read-only/aws"
  version       = "0.3.1" // Please make sure this is the latest release!
  customer_name = "acme"  // Should be the customer name as registered when signing up
  aws_profile   = "dev"   // If using a default set of credentials, should be set to null
}
```

### Finding the relevant automations
When running the following command:
```shell script
airiam remove_unused [-p PROFILE] [-l LAST_SEEN_THRESHOLD]
```
The expected output will be the unused entities, together with links to `Bridgecrew`s playbooks. Clicking these links
will redirect you to your [Bridgecrew Cloud](https://www.bridgecrew.cloud) account, where you can see the remediation 
script, download and use it.

## Integration with Checkov
[Checkov](https://www.checkov.io) allows static analysis of terraform code (as well as cloudformation)
