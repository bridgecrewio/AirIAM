import datetime
import json
import unittest
from unittest.mock import patch

import boto3
from moto import mock_iam

from airiam.main import configure_logger
from airiam.find_unused.RuntimeIamScanner import RuntimeIamScanner

ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
READ_ONLY_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'


class TestRuntimeIamEvaluator(unittest.TestCase):
    def test_simplify_service_access_result(self):
        service_last_access = [
            {
                "ServiceName": "Alexa for Business",
                "ServiceNamespace": "a4b",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "IAM Access Analyzer",
                "ServiceNamespace": "access-analyzer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Accounts",
                "ServiceNamespace": "account",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Certificate Manager",
                "ServiceNamespace": "acm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Certificate Manager Private Certificate Authority",
                "ServiceNamespace": "acm-pca",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Amplify",
                "ServiceNamespace": "amplify",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Manage - Amazon API Gateway",
                "ServiceNamespace": "apigateway",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Application Auto Scaling",
                "ServiceNamespace": "application-autoscaling",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "CloudWatch Application Insights",
                "ServiceNamespace": "applicationinsights",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS App Mesh",
                "ServiceNamespace": "appmesh",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS App Mesh Preview",
                "ServiceNamespace": "appmesh-preview",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon AppStream 2.0",
                "ServiceNamespace": "appstream",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS AppSync",
                "ServiceNamespace": "appsync",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Application Discovery Arsenal",
                "ServiceNamespace": "arsenal",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Artifact",
                "ServiceNamespace": "artifact",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Athena",
                "ServiceNamespace": "athena",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon EC2 Auto Scaling",
                "ServiceNamespace": "autoscaling",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Auto Scaling",
                "ServiceNamespace": "autoscaling-plans",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Marketplace",
                "ServiceNamespace": "aws-marketplace",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Marketplace Management Portal",
                "ServiceNamespace": "aws-marketplace-management",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Billing",
                "ServiceNamespace": "aws-portal",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Backup",
                "ServiceNamespace": "backup",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Backup storage",
                "ServiceNamespace": "backup-storage",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Batch",
                "ServiceNamespace": "batch",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Budget Service",
                "ServiceNamespace": "budgets",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Managed Apache Cassandra Service",
                "ServiceNamespace": "cassandra",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Cost Explorer Service",
                "ServiceNamespace": "ce",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Chatbot",
                "ServiceNamespace": "chatbot",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Chime",
                "ServiceNamespace": "chime",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Cloud9",
                "ServiceNamespace": "cloud9",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Cloud Directory",
                "ServiceNamespace": "clouddirectory",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CloudFormation",
                "ServiceNamespace": "cloudformation",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CloudFront",
                "ServiceNamespace": "cloudfront",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CloudHSM",
                "ServiceNamespace": "cloudhsm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CloudSearch",
                "ServiceNamespace": "cloudsearch",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CloudTrail",
                "ServiceNamespace": "cloudtrail",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CloudWatch",
                "ServiceNamespace": "cloudwatch",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodeBuild",
                "ServiceNamespace": "codebuild",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodeCommit",
                "ServiceNamespace": "codecommit",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodeDeploy",
                "ServiceNamespace": "codedeploy",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CodeGuru Profiler",
                "ServiceNamespace": "codeguru-profiler",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CodeGuru Reviewer",
                "ServiceNamespace": "codeguru-reviewer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodePipeline",
                "ServiceNamespace": "codepipeline",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodeStar",
                "ServiceNamespace": "codestar",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS CodeStar Notifications",
                "ServiceNamespace": "codestar-notifications",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Cognito Identity",
                "ServiceNamespace": "cognito-identity",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Cognito User Pools",
                "ServiceNamespace": "cognito-idp",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Cognito Sync",
                "ServiceNamespace": "cognito-sync",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Comprehend",
                "ServiceNamespace": "comprehend",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Comprehend Medical",
                "ServiceNamespace": "comprehendmedical",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Compute Optimizer",
                "ServiceNamespace": "compute-optimizer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Config",
                "ServiceNamespace": "config",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Connect",
                "ServiceNamespace": "connect",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Cost and Usage Report",
                "ServiceNamespace": "cur",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Data Exchange",
                "ServiceNamespace": "dataexchange",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Data Pipeline",
                "ServiceNamespace": "datapipeline",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "DataSync",
                "ServiceNamespace": "datasync",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon DynamoDB Accelerator (DAX)",
                "ServiceNamespace": "dax",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Database Query Metadata Service",
                "ServiceNamespace": "dbqms",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS DeepLens",
                "ServiceNamespace": "deeplens",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS DeepRacer",
                "ServiceNamespace": "deepracer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Detective",
                "ServiceNamespace": "detective",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Device Farm",
                "ServiceNamespace": "devicefarm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Direct Connect",
                "ServiceNamespace": "directconnect",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Application Discovery Service",
                "ServiceNamespace": "discovery",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Data Lifecycle Manager",
                "ServiceNamespace": "dlm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Database Migration Service",
                "ServiceNamespace": "dms",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Directory Service",
                "ServiceNamespace": "ds",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon DynamoDB",
                "ServiceNamespace": "dynamodb",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elastic Block Store",
                "ServiceNamespace": "ebs",
                "TotalAuthenticatedEntities": 0
            },
            {
                "LastAuthenticated": "2019-08-05T08:56:00+00:00",
                "LastAuthenticatedEntity": "arn:aws:iam::098885917934:user/user-jenkins",
                "ServiceName": "Amazon EC2",
                "ServiceNamespace": "ec2",
                "TotalAuthenticatedEntities": 1
            },
            {
                "ServiceName": "Amazon EC2 Instance Connect",
                "ServiceNamespace": "ec2-instance-connect",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Message Delivery Service",
                "ServiceNamespace": "ec2messages",
                "TotalAuthenticatedEntities": 0
            },
            {
                "LastAuthenticated": "2020-02-05T11:41:00+00:00",
                "LastAuthenticatedEntity": "arn:aws:iam::098885917934:user/user-jenkins",
                "ServiceName": "Amazon Elastic Container Registry",
                "ServiceNamespace": "ecr",
                "TotalAuthenticatedEntities": 1
            },
            {
                "LastAuthenticated": "2020-02-10T13:23:00+00:00",
                "LastAuthenticatedEntity": "arn:aws:iam::098885917934:user/user-jenkins",
                "ServiceName": "Amazon Elastic Container Service",
                "ServiceNamespace": "ecs",
                "TotalAuthenticatedEntities": 1
            },
            {
                "ServiceName": "Amazon Elastic Container Service for Kubernetes",
                "ServiceNamespace": "eks",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elastic Inference",
                "ServiceNamespace": "elastic-inference",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon ElastiCache",
                "ServiceNamespace": "elasticache",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elastic Beanstalk",
                "ServiceNamespace": "elasticbeanstalk",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elastic File System",
                "ServiceNamespace": "elasticfilesystem",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Elastic Load Balancing",
                "ServiceNamespace": "elasticloadbalancing",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elastic MapReduce",
                "ServiceNamespace": "elasticmapreduce",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elastic Transcoder",
                "ServiceNamespace": "elastictranscoder",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Elasticsearch Service",
                "ServiceNamespace": "es",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon EventBridge",
                "ServiceNamespace": "events",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon API Gateway",
                "ServiceNamespace": "execute-api",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Kinesis Firehose",
                "ServiceNamespace": "firehose",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Firewall Manager",
                "ServiceNamespace": "fms",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Forecast",
                "ServiceNamespace": "forecast",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Fraud Detector",
                "ServiceNamespace": "frauddetector",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon FreeRTOS",
                "ServiceNamespace": "freertos",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon FSx",
                "ServiceNamespace": "fsx",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon GameLift",
                "ServiceNamespace": "gamelift",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Glacier",
                "ServiceNamespace": "glacier",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Global Accelerator",
                "ServiceNamespace": "globalaccelerator",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Glue",
                "ServiceNamespace": "glue",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT Greengrass",
                "ServiceNamespace": "greengrass",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Ground Station",
                "ServiceNamespace": "groundstation",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon GroundTruth Labeling",
                "ServiceNamespace": "groundtruthlabeling",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon GuardDuty",
                "ServiceNamespace": "guardduty",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Health APIs and Notifications",
                "ServiceNamespace": "health",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Identity and Access Management",
                "ServiceNamespace": "iam",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon EC2 Image Builder",
                "ServiceNamespace": "imagebuilder",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Import Export",
                "ServiceNamespace": "importexport",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Inspector",
                "ServiceNamespace": "inspector",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT",
                "ServiceNamespace": "iot",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT 1-Click",
                "ServiceNamespace": "iot1click",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT Analytics",
                "ServiceNamespace": "iotanalytics",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT Events",
                "ServiceNamespace": "iotevents",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT SiteWise",
                "ServiceNamespace": "iotsitewise",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IoT Things Graph",
                "ServiceNamespace": "iotthingsgraph",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IQ",
                "ServiceNamespace": "iq",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS IQ Permissions",
                "ServiceNamespace": "iq-permission",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Managed Streaming for Kafka",
                "ServiceNamespace": "kafka",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Kendra",
                "ServiceNamespace": "kendra",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Kinesis",
                "ServiceNamespace": "kinesis",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Kinesis Analytics",
                "ServiceNamespace": "kinesisanalytics",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Kinesis Video Streams",
                "ServiceNamespace": "kinesisvideo",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Key Management Service",
                "ServiceNamespace": "kms",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Lake Formation",
                "ServiceNamespace": "lakeformation",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Lambda",
                "ServiceNamespace": "lambda",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Launch Wizard",
                "ServiceNamespace": "launchwizard",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Lex",
                "ServiceNamespace": "lex",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS License Manager",
                "ServiceNamespace": "license-manager",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Lightsail",
                "ServiceNamespace": "lightsail",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CloudWatch Logs",
                "ServiceNamespace": "logs",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Machine Learning",
                "ServiceNamespace": "machinelearning",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Macie",
                "ServiceNamespace": "macie",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Managed Blockchain",
                "ServiceNamespace": "managedblockchain",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Mechanical Turk",
                "ServiceNamespace": "mechanicalturk",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaConnect",
                "ServiceNamespace": "mediaconnect",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaConvert",
                "ServiceNamespace": "mediaconvert",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaLive",
                "ServiceNamespace": "medialive",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaPackage",
                "ServiceNamespace": "mediapackage",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaPackage VOD",
                "ServiceNamespace": "mediapackage-vod",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaStore",
                "ServiceNamespace": "mediastore",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Elemental MediaTailor",
                "ServiceNamespace": "mediatailor",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Migration Hub",
                "ServiceNamespace": "mgh",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Mobile Analytics",
                "ServiceNamespace": "mobileanalytics",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Mobile Hub",
                "ServiceNamespace": "mobilehub",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Pinpoint",
                "ServiceNamespace": "mobiletargeting",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon MQ",
                "ServiceNamespace": "mq",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Neptune",
                "ServiceNamespace": "neptune-db",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Network Manager",
                "ServiceNamespace": "networkmanager",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS OpsWorks",
                "ServiceNamespace": "opsworks",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS OpsWorks Configuration Management",
                "ServiceNamespace": "opsworks-cm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Organizations",
                "ServiceNamespace": "organizations",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Outposts",
                "ServiceNamespace": "outposts",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Personalize",
                "ServiceNamespace": "personalize",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Performance Insights",
                "ServiceNamespace": "pi",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Polly",
                "ServiceNamespace": "polly",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Price List",
                "ServiceNamespace": "pricing",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon QLDB",
                "ServiceNamespace": "qldb",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon QuickSight",
                "ServiceNamespace": "quicksight",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Resource Access Manager",
                "ServiceNamespace": "ram",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon RDS",
                "ServiceNamespace": "rds",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon RDS Data API",
                "ServiceNamespace": "rds-data",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon RDS IAM Authentication",
                "ServiceNamespace": "rds-db",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Redshift",
                "ServiceNamespace": "redshift",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Rekognition",
                "ServiceNamespace": "rekognition",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Resource Groups",
                "ServiceNamespace": "resource-groups",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS RoboMaker",
                "ServiceNamespace": "robomaker",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Route 53",
                "ServiceNamespace": "route53",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Route53 Domains",
                "ServiceNamespace": "route53domains",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Route 53 Resolver",
                "ServiceNamespace": "route53resolver",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon S3",
                "ServiceNamespace": "s3",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon SageMaker",
                "ServiceNamespace": "sagemaker",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Savings Plans",
                "ServiceNamespace": "savingsplans",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon EventBridge Schemas",
                "ServiceNamespace": "schemas",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon SimpleDB",
                "ServiceNamespace": "sdb",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Secrets Manager",
                "ServiceNamespace": "secretsmanager",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Security Hub",
                "ServiceNamespace": "securityhub",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Serverless Application Repository",
                "ServiceNamespace": "serverlessrepo",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Service Catalog",
                "ServiceNamespace": "servicecatalog",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Cloud Map",
                "ServiceNamespace": "servicediscovery",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Service Quotas",
                "ServiceNamespace": "servicequotas",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon SES",
                "ServiceNamespace": "ses",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Shield",
                "ServiceNamespace": "shield",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Code Signing for Amazon FreeRTOS",
                "ServiceNamespace": "signer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Server Migration Service",
                "ServiceNamespace": "sms",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Pinpoint SMS and Voice Service",
                "ServiceNamespace": "sms-voice",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Snowball",
                "ServiceNamespace": "snowball",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon SNS",
                "ServiceNamespace": "sns",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon SQS",
                "ServiceNamespace": "sqs",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Systems Manager",
                "ServiceNamespace": "ssm",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Session Manager Message Gateway Service",
                "ServiceNamespace": "ssmmessages",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS SSO",
                "ServiceNamespace": "sso",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS SSO Directory",
                "ServiceNamespace": "sso-directory",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Step Functions",
                "ServiceNamespace": "states",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Storage Gateway",
                "ServiceNamespace": "storagegateway",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Security Token Service",
                "ServiceNamespace": "sts",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Sumerian",
                "ServiceNamespace": "sumerian",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Support",
                "ServiceNamespace": "support",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Simple Workflow Service",
                "ServiceNamespace": "swf",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon CloudWatch Synthetics",
                "ServiceNamespace": "synthetics",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Resource Group Tagging API",
                "ServiceNamespace": "tag",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Textract",
                "ServiceNamespace": "textract",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Transcribe",
                "ServiceNamespace": "transcribe",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "AWS Transfer for SFTP",
                "ServiceNamespace": "transfer",
                "TotalAuthenticatedEntities": 0
            },
            {
                "ServiceName": "Amazon Translate",
                "ServiceNamespace": "translate",
                "TotalAuthenticatedEntities": 0
            }
        ]
        simplified = RuntimeIamScanner.simplify_service_access_result(service_last_access)
        self.assertEqual(len(simplified), 3)
        for last_access in simplified:
            self.assertIsInstance(datetime.datetime.fromisoformat(last_access['LastAccessed']), datetime.date)

    def test_convert_csv_to_json(self):
        csv_str = 'name,type,last_access\nhatulik,role,2019-08-05T08:56:00+00:00\nshati,user,2020-02-05T10:56:00+00:00'
        json_csv = RuntimeIamScanner.convert_csv_to_json(csv_str)
        self.assertEqual(len(json_csv), 2)
        self.assertListEqual(['name', 'type', 'last_access'], list(json_csv[0].keys()))
        self.assertListEqual(list(json_csv[0].keys()), list(json_csv[1].keys()))

    @mock_iam
    def test_iam_calls(self):
        with patch.dict('os.environ', {"AWS_ACCESS_KEY_ID": "FAKE", "AWS_SECRET_ACCESS_KEY": "FAKE"}):
            client = boto3.client('iam')
            self.create_user(client, 'test@bridgecrew.io')
            self.create_role(client, 'bc-role', ADMIN_POLICY_ARN)
            self.create_role(client, 'bc-role2', READ_ONLY_ARN)
            client.create_group(GroupName='admins', Path='/')
            client.attach_group_policy(GroupName='admins', PolicyArn=ADMIN_POLICY_ARN)
            client.create_group(GroupName='read-only', Path='/')
            client.attach_group_policy(GroupName='read-only', PolicyArn=READ_ONLY_ARN)
            client.add_user_to_group(GroupName='admins', UserName='test@bridgecrew.io')
            client.add_user_to_group(GroupName='read-only', UserName='test@bridgecrew.io')
            logger = configure_logger()
            iam_data = RuntimeIamScanner(logger)._get_data_from_aws("000000000000", False)
        self.assertTrue(len(iam_data.keys()) == 5)

    @staticmethod
    def create_user(client, user_name):
        client.create_user(Path='/', UserName=user_name)
        client.create_login_profile(UserName=user_name, Password='TempPass123', PasswordResetRequired=True)
        client.create_access_key(UserName=user_name)

    @staticmethod
    def create_role(client, role_name, policy_arn_to_attach):
        client.create_role(Path='/', RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Actions": ["sts:AssumeRole"],
                    "Principal": {
                        "Type": "Service",
                        "Identifiers": ["ec2.amazonaws.com"]
                    }
                }
            ]
        }))
        client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn_to_attach)


if __name__ == '__main__':
    unittest.main()
