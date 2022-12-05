
# Control Tower - Customization Pipeline

## Roles

- ### *Control Tower Execution Role*

  - Create a *Control Tower Execution Role* in the Management Account. This role will allow CloudFormation StackSets to be deployed within the Management account through the customization pipeline. Use the cloudformation template `management-control-tower-execution-role.yaml` and deploy this template manually in CloudFormation. No further modifications or updates will be required.

- ### *Control Tower Account Alias Role*

  - Create a *Control Tower Account Alias Role* in the Management Account. This role will be used to describe the accounts in the organization. When deploying the customization for the Account Alias, the Lambda function will switch and assume this role to perform these actions. Use the cloudformation template `management-control-tower-alias-role.yaml` and deploy this template manually in CloudFormation. No further modifications or updates will be required.

---

## Prerequisite Customizations

- ### *SSM Account Parameters*

  - The SSM Account Parameters pre-work customization will trigger a lifecycle event to deploy the creation of SSM parameters for the AWS Organization ID and all member accounts. This will deploy a single stack instance within the management account. Use the cloudformation template `management-control-tower-ssm-account-params.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pLambdaFunctionName` | ssm-account-parameter-creator  | The value for this parameter will be the name for the lambda function.        |
| `pLambdaRoleName`     | ssm-account-parameter-creator  |   The value for this parameter will be the name for the Lambda role.      |

- ### *S3 Artifacts Bucket*

  - An S3 bucket will be created and used to store objects such as Lambda code, etc. This will deploy a single stack instance within the management account. Use the cloudformation template `management-control-tower-s3-bucket.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pBucketNamePrefix` | custom-control-tower-artifacts  | The value for this parameter will be S3 Bucket prefix name.        |
| `pOrganizationId`    | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/primary/organization_id]***. Otherwise, pass in the value string. |   The value for this parameter will be Organization ID.      |

- ### *Support Case*

  - Prior to deploying this customization, you must login with the root credentials on the management account and manually change the support plan to business support. A lifecycle event will be deployed to trigger the creation of an AWS support case whenever a new AWS account is enrolled in Control Tower. This will deploy a single stack instance within the management account. Use the cloudformation template `management-control-tower-support.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pEmailAddress` | ***test@jpl.nasa.gov***  | The email address that will be used to send inquiries for newly created accounts that must be added to the Control Tower's management enterprise support.        |
| `pSnsTopicName`     | control-tower-lifecycle-event-enterprise-support  |   The name for the SNS topic.      |

- ### *CloudCheckr CMx*

  - CloudCheckr CMx will be integrated with your AWS Control Tower environment to automatically enroll accounts into CloudCheckr CMx upon creation. This will deploy a single stack instance within the management account. Use the cloudformation template `management-control-tower-cloudcheckr-integration.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pApiClientId`      | Create an SSM Parameter with your CloudCheckr client ID then retrieve the value by using this function --> ***$[alfred_ssm_/org/cloudcheckr/client/client-id]***       |   The value for this parameter will be the CloudCheckr Client ID which is retrieve from the CloudCheckr CMx console.  |
| `pApiClientSecret`  | Create an SSM Parameter with your CloudCheckr secret then retrieve the value by using this function ***$[alfred_ssm_/org/cloudcheckr/client/client-secret]***  |  The value for this parameter will be the CloudCheckr Client secret which is retrieve from the CloudCheckr CMx console.  |     |
| `pApiClientEndpoint`      | US       |   CloudCheckr API Endpoint to use.  |
| `pApiClientRegionGroup`      | Commercial       |   CloudCheckr API Region Group for Accounts Credentials Setup.  |
| `pLambdaBucket`      | cc-public-resources       |   The prefix of the S3 bucket containing the Lambda package and templates.  |
| `pLambdaPath`      | packages/cc_ct_integration_1.0.0.zip       |   The path to the lambda package file within the bucket.  |
| `pSnsTopicName`      | CloudCheckr-Control-Tower-Integration-Topic      |   SNS Topic to which the Lambda will push notifications in case of failure or important notifications.  |
| `pExternalAccount`      | 352813966189       |   CloudCheckr Account ID for cross-account trust.  |
| `pStackSetName`      | CloudCheckr-ControlTower-StackSet      |   Name for the StackSet to create stack instances in new accounts.  |
| `pStackSetTemplateUrl`      | [https://cc-public-resources-us-east-1.s3.amazonaws.com/templates/cc_aws_cfn_iam_stack.template.json](https://cc-public-resources-us-east-1.s3.amazonaws.com/templates/cc_aws_cfn_iam_stack.template.json)       |   S3 URL of the CloudFormation template for new accounts. Change the region name suffix on the URL to the Control Tower supported region you are deploying into.  |

---

## Customizations

- ### *Account Alias*

  - The Account Alias customization will deploy a custom resource to create or modify the alias for the AWS account. In order for this customization to be successful, all accounts specified must have valid characters. The alias must be not more than 63 characters. Valid characters are a-z, 0-9, and - (hyphen). View the example code snippet below. The `management-control-tower-alias-role.yaml` must be deployed prior to this customization. Use the cloudformation template `aws-control-tower-account-alias.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pPrefix`      | nasa       |   The value for this parameter will be the prefix that is added to the account alias. (e.g. jet-prop-lab-aws@jpl.nasa.gov --> nasa-jet-prop-lab)  |
| `pFindMatchingString`  | -aws  |  The value for this parameter will be the matching string such as '-aws' which will be removed/omitted from the AWS account email to form the account alias name. (e.g. jet-prop-lab-aws@jpl.nasa.gov --> jet-prop-lab) |     |
| `pOrgMasterAccountId`      | After you've successful deployed the SSM parameters prereq, you can pull the value using this function (replace the name of the management account) --> ***$[alfred_ssm_/org/member/\<The Name of the Management Account\>/account_id]***   |   The value for this parameter is the Management Account ID.  |
| `pReadAWSOrganizationsRoleName`      | ReadAWSOrganizationsRole       |   The value for this parameter is the name of the role that will be used to assume role from the member accounts into the management account in order to describe all the accounts in the AWS Organizations.  |

- ### *Identity Provider*

  - The Identity Provider customization will deploy a custom resource to create or modify the idP for the AWS account. In order for this customization to be successful, you must have a valid xml file, which is stored in an S3 bucket. Use the cloudformation template `aws-control-tower-account-saml-idP.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pSamlProviderName`      | Federation_idP       |   The value for this parameter will be the name of the Identity Provider.  |
| `pSamlMetadataBucket`  | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/primary/custom-control-tower-artifacts/us-west-2]***  | The value for this parameter will be S3 Artifacts bucket where code and other files reside. |
| `pSamlMetadataFilename`      | FederationMetadata(SSO2_PROD).xml   |   The value for this parameter is the name of the SAML Metadata file.  |

- ### *Password Policy*

  - The Password Policy customization will deploy a custom resource to update the password policy for the AWS account. In order for this customization to be successful, all conditions must be set to pass as environment variables within the Lambda function. Use the cloudformation template `aws-control-tower-account-set-password-policy.yaml` and pass the following parameters below:

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pRequireUppercaseCharacters`      | True       |   Require Uppercase Characters in Password.  |
| `pRequireLowercaseCharacters`  | True  | Require Lowercase Characters in Password. |
| `pRequireSymbols`      | True   |  Require Symbols in Password.  |
| `pRequireNumbers`      | True   |   Require Numbers in Password.  |
| `pMinimumPasswordLength`      | 14   |   Require Minimum Password Length.  |
| `pPasswordReusePrevention`      | 24   |   Restrict password reuse to at least a number of resets.  |
| `pMaxPasswordAge`      | 90   |   Restrict max password age in days.  |
| `pAllowUsersToChangePassword`      | True   |  Allow users to change their passwords.  |
| `pHardExpiry`      | False   |   Restrict reset of expired passwords.  |

- ### *GuardDuty*

  - The GuardDuty Organization solution will enable Amazon GuardDuty by delegating administration to a member account within the Organization management account and configuring GuardDuty within the delegated administrator account for all the existing and future AWS Organization accounts. GuardDuty is also configured to send the findings to a central S3 bucket encrypted with a KMS key and S3 Protection is enabled. Use the cloudformation template `guardduty-org-delivery-kms-key.yaml`,  `guardduty-org-delivery-s3-bucket.yaml`, and `guardduty-inviter.yaml` pass the following parameters below:

#### *GuardDuty KMS Key*

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pGuardDutyDeliveryKeyAlias`      | GuardDutyDeliveryKMSKey       |   The KMS Key to encrypt the GuardDuty findings for the S3 bucket.  |
| `pLoggingAccountId`  | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/member/Log-Archive/account_id]***  | The value for this parameter is the Log Archive ID. |
| `pOrgPrimaryAccountId`      | After you've successful deployed the SSM parameters prereq, you can pull the value using this function (replace the name of the management account) -->  ***$[alfred_ssm_/org/member/\<The Name of the Management Account\>/account_id]***  |  The value for this parameter is the Management Account ID.  |
| `pTagKey1`      | cfct   |  Tag key name.  |
| `pTagValue1`      | managed-by-cfct   |   Tag key value.  |

#### *GuardDuty S3 Bucket*

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pGuardDutyDeliveryBucketPrefix`      | cfct-guardduty-delivery       |   The S3 Bucket used to store GuardDuty findings.  |
| `pGuardDutyDeliveryKMSKeyArn`  | After you've successful deployed the GuardDuty KMS Key, you can pull the value using this function --> ***$[alfred_ssm_/org/guardduty/kms_key_arn]***  | The KMS Key to encrypt the GuardDuty findings for the S3 bucket. |
| `pTagKey1`      | cfct   |  Tag key name.  |
| `pTagValue1`      | managed-by-cfct   |   Tag key value.  |

#### *GuardDuty Inviter*

| Parameter Key       | Parameter Value | Description |
| -----------         | -----------     |-----------  |
| `pLambdaFunctionName`      | guardduty-org-inviter      |   The Lambda function name.  |
| `pAuditAccountId`  | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/member/Audit/account_id]***  | The value for this parameter is the Audit ID. |
| `pOrganizationId`      | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/primary/organization_id]***   |  The value for this parameter will be Organization ID.  |
| `pLambdaS3BucketName`      | After you've successful deployed the SSM parameters prereq, you can pull the value using this function --> ***$[alfred_ssm_/org/primary/custom-control-tower-artifacts/us-west-2]***   |   The value for this parameter will be S3 Artifacts bucket where code and other files reside.  |
| `pLambdaZipFileName`      | ControlTower-GuardDutyInviter.zip   |   The value for this parameter will be S3 artifacts key.  |
| `pRoleToAssume`      | AWSControlTowerExecution   |   The Control Tower Execution Role to assume into the account.  |
| `pPublishingDestinationBucketName`      | After you've successful deployed the GuardDuty Destination S3 Bucket, you can pull the value using this function --> ***$[alfred_ssm_/org/guardduty/s3_bucket]***   |   The S3 Bucket used to store GuardDuty findings.  |
| `pGuardDutyDeliveryKMSKeyArn`      | After you've successful deployed the GuardDuty KMS Key, you can pull the value using this function --> ***$[alfred_ssm_/org/guardduty/kms_key_arn]***   |  The KMS Key to encrypt the GuardDuty findings for the S3 bucket.  |

---

# References

- [https://aws.amazon.com/blogs/mt/automating-service-limit-increases-enterprise-support-aws-control-tower/](https://aws.amazon.com/blogs/mt/automating-service-limit-increases-enterprise-support-aws-control-tower/)

- [https://aws.amazon.com/blogs/awsmarketplace/integrating-the-cloudcheckr-cmx-cloud-management-platform-with-aws-control-tower/](https://aws.amazon.com/blogs/awsmarketplace/integrating-the-cloudcheckr-cmx-cloud-management-platform-with-aws-control-tower/)

- [https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWS-CloudCheckr-Implementation-Guide.pdf](https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWS-CloudCheckr-Implementation-Guide.pdf)

- [https://controltower.aws-management.tools/automation/cfct/](https://controltower.aws-management.tools/automation/cfct/)

- [https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html](https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html)

- [https://aws.amazon.com/blogs/architecture/field-notes-enroll-existing-aws-accounts-into-aws-control-tower/](ttps://aws.amazon.com/blogs/architecture/field-notes-enroll-existing-aws-accounts-into-aws-control-tower/)


