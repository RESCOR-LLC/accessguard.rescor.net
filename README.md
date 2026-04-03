# AccessGuard (IAM &amp; SSO Auditing and RBAC Engineering Tool)

DRAFT

# Table of Contents

_**[Introduction 3](#_Toc88043299)**_

**[Purpose 3](#_Toc88043300)**

**[AWS GovCloud Considerations 3](#_Toc88043301)**

**[Installation &amp; Operation 3](#_Toc88043302)**

**[Process Description &amp; Data Formats 5](#_Toc88043303)**

**[Inline Policies in the IAM Entities Sheet 7](#_Toc88043304)**

_**[Command Reference 10](#_Toc88043305)**_

**[IAM &amp; SSO Cataloging and Role Engineering (accessGuard.py) 10](#_Toc88043306)**

[Example 10](#_Toc88043307)

# Introduction

## Purpose

AccessGuard is a multi-account IAM and SSO auditing and role-based access control (RBAC) engineering tool. Use AccessGuard to produce a catalog of all IAM users, groups, roles, and AWS SSO permission sets for auditors (does not require the auditor to have access to your AWS environment). AccessGuard also facilitates RBAC role engineering by detecting similar users, groups, and roles and allowing comparison with SSO permission sets to produce a minimum set of well-engineering RBAC roles. AccessGuard produces the following output:

- A catalog of existing AWS IAM entities (users, groups, and roles) and AWS SSO permission sets (if applicable)
- A list of similar IAM users, groups, and roles based on similar managed policies and similar membership (for groups)

_ **IMPORTANT!** _ &quot;Role engineering&quot; refers to role-based access control (RBAC), which does not necessarily refer to IAM roles. RBAC roles may correspond to IAM roles, IAM groups, or SSO permission sets. An RBAC role is a functional role, whereas an IAM role is a permissions role.

## AWS GovCloud Considerations

AccessGuard supports GovCloud for IAM auditing and RBAC engineering.

- GovCloud does not currently support AWS Single Sign-On (SSO) so you should omit the **–sso-region** option
- You must specify the AWS partition &quot; **aws-us-gov**&quot; to access GovCloud regions

## The Configuration File

You configure AccessGuard using a CSV file. Each row of the CSV file has six columns. These columns are as follows:

1. AccountId – the 12-digit AWS account number
2. Nickname – a nickname you choose for this account
3. AssumableRole – a full AWS role ARN which AccessGuard assumes to gain access to this account. This allows AccessGuard to audit accounts that are not in an AWS Organization.
4. Partition – The AWS partition name for this account. For US commercial regions this is &quot;aws-us&quot;; For US GovCloud regions this is &quot;aws-us-gov&quot;
5. DefaultRegion – The region name in which all API operations are performed by default, and in which the AgDatastore CloudFormation stack was created.
6. SSORegion – The region in which your AWS SSO environment is defined. This is not supported for US GovCloud regions.

You execute AccessGuard with the –configuration option to read this file and store it in a DynamoDB table. The configuration table is keyed by account ID, so the existing configuration for an account will be replaced whenever you perform a configuration. However, if a new configuration file does not contain an account ID, any existing entry for that account ID is _not_ removed.

## Installation &amp; Operation

AccessGuard runs as a Lambda function, and it can also be run as a command line function from your terminal.

1. If you will be running AccessGuard as a terminal command your environment must be as follows:
  1. Python 3.8 or greater
  2. AWS CLI installed
  3. AWS BOTO3 installed
  4. The details of how you authenticate to your AWS account(s) are not covered here
2. Populate the **accessGuard-account-configuration.csv** file with the following information (you can call this file anything you want):
  1. The AWS account number
  2. A nickname for the AWS account
  3. An assumable role to use for that account (if applicable)
  4. The partition name of the account
  5. The default region in which IAM, DynamoDB, and S3 operations will be performed
  6. The SSO region (if applicable)

You may store this file locally if you will use AccessGuard from the command line, or you can store it in an S3 bucket if you will use AccessGuard as a Lambda function.

1. Create a CloudFormation stack using the template **AgDatastore.yaml**. This template creates DynamoDB tables, an S3 bucket, and a series of SSM parameters.
2. Create a ZIP file containing all Python files and upload that file to the bucket created in step (2). The following example uses the S3 API but you can use any equivalent method including the AWS console.
  1. Change to the AccessGuard distribution directory
  2. **zip AccessGuard.zip ./\*.py**
  3. **aws ssm get-parameter --name /AccessGuard/Bucket --region us-gov-west-1**
  4. Obtain the bucket name from the results of (3.3)
  5. **aws s3api put-object --bucket** _bucketName_ **--key Code/AccessGuard.zip –body AccessGuard.zip**
  6. NOTE: You can use any name for the zip file in (3.2), and you must use a unique key in step (3.5) each time you install a new version of the AccessGuard code.
3. Create a CloudFormation stack using the template **AgInstaller.yaml**. This template creates the Lambda function and an IAM role containing the necessary privileges to execute the Lambda.
4. Configure AccessGuard from the CSV file you created or updated in step (2).
  1. AWS CLI: **./accessGuard.py --configuration** _localCsv_ **-o . --default-region** _regionName_
  2. AWS Lambda from CLI: **aws invoke –function-name** _nameFromStep5_ **–payload &#39;{ &quot;configuration&quot;:** _s3UrlToCsv_ **, &quot;output&quot; : &quot;s3&quot; }&#39;**
  3. Commercial Regions: **python3 access-guard.py –sso-region=** \&lt;\&lt;SsoRegion\&gt;\&gt; **–iam-region**** =**\&lt;\&lt;IamRegion\&gt;\&gt;
  4. GovCloud Regions: **python3 access-guard.py –partition=aws-us-gov –iam-region**** =**\&lt;\&lt;GovCloudIamRegion\&gt;\&gt;
  5. Where:
    1. \&lt;\&lt;IamRegion\&gt;\&gt; is any region in which you operate AWS resources
    2. \&lt;\&lt;SsoRegion\&gt;\&gt; is the region in which your AWS Single Sign-On instance resides (not supported in GovCloud).
    3. \&lt;\&lt;GovCloudIamRegion\&gt;\&gt; is any GovCloud region in which you operate AWS resources
5. Accept the Excel prompt to _Enable macros_

## Process Description &amp; Data Formats

The AccessGuard Python program reads account and assumable role information from, and writes its results to, the AccessGuard spreadsheet.

1. **Multi Account Support –** the assumable role for _each_ account listed in the _AWS Accounts &amp; Roles_ sheet is assumed (if there is no assumable role, credentials are inherited from your environment or your AWS configuration file).
2. **Access Catalog**. IAM users, groups, and roles and SSO permission sets (if applicable) are enumerated, as well as the managed policies attached to each, and any inline policies in JSON format. This catalog may be written as JSON items to DynamoDB, or as CSV files to S3 or local files.
  1. JSON Format (DynamoDB)

**{**

**&quot;id&quot;:** _sha256hash_ **,**

**&quot;reportDate&quot;:** _isoDateStampWhenReportRun_ **,**

**&quot;policy&quot;: {** _inlinePolicyJson_ **},**

**&quot;managed&quot;: [** _listOfManagedPolicyNames_ **],**

**&quot;members&quot;: [** _memberListForGroup_ **],**

**&quot;account&quot;:** _accountId_ **,**

**&quot;TTL&quot;:** _expirationEpochDate_ **,**

**&quot;description&quot;:** _entityDescription_ **,**

**&quot;name&quot;:** _entityName_ **,**

**&quot;arn&quot;:** _entityArn_ **,**

**&quot;type&quot;: &quot;User** | **Group** | **Role** | **Permission-Set&quot;**

**}**

  1. CSV Format (S3 and local files, by column name, as appear in the first row of the CSV file)
    1. ReportDate – the ISO date stamp when the report was run (will unify all catalog entries from a specific date)
    2. ReportItemId – a SHA256 hash of the report date, entity type, and entity name (will be unique for all entities)
    3. EntityName – the name of the IAM or SSO entity
    4. EntityArn – the ARN of the IAM or SSO entity
    5. EntityDescription – the description of the entity if any
    6. EntityAccount – the account ID in which the entity appears
    7. Entity Type – user, group, role, or permission-set
    8. EntityMembers – JSON list of members of a Group entity
    9. EntityManaged – JSON list of managed policies associated with entity
    10. EntityPolicy – JSON object of inline policies attached to entity (see notes below)

1. **Similarity List.** IAM users, groups, and roles are analyzed to identify similar entities based on managed policies (users, groups, and roles) and group membership (groups only). The results are written to the _Similar Entities_ sheet as follows:
  1. JSON Format(DynamoDB)

**{**

**&quot;id&quot;:** _sha256hash_ **,**

**&quot;reportDate&quot;:** _isoDateStampWhenReportRun_ **,**

**&quot;by&quot;: [** _similarityBasis_ **],**

**&quot;entities&quot;: [** _listOfSimilarEntities_ **],**

**&quot;TTL&quot;:** _expirationEpochDate_ **,**

**&quot;similarity&quot;: &quot;Managed Policies** | **Group Membership&quot;**

**}**

  1. CSV Format (S3 and local files)
    1. ReportDate – the ISO date stamp when the report was run (will unify all catalog entries from a specific date)
    2. ReportRowId – a SHA256 hash of the report date and similar entity IDs (will be unique for all entities)
    3. SimilarityType -- criterion by which the entities are similar (&quot;Managed Policies&quot; or &quot;Group Membership&quot;)
    4. SimilarBy – a list of group members or managed policy names shared by the similar entities
    5. SimilarEntities– a list of entities that are similar according to the SimilarBy

The _Similarity List_ can be used to identify unnecessary users, roles, and groups that have the same set of managed policies, and unnecessary groups that have the same group membership. It is not necessarily the case that all similar entities are unnecessary—that is a judgement that must be made by the customer and the customer&#39;s AWS ProServe team.

AccessGuard may take several minutes to complete. Refer to the terminal window you opened in the installation section above for debugging and error messages.

## Inline Policies in the IAM Entities Sheet

Because multiple inline policies may be associated with an IAM entity, each policy is presented in an associative structure (dict, hash) as follows:

{

_\&lt;\&lt;PolicyName\&gt;\&gt;_: _\&lt;\&lt;PolicyJson\&gt;\&gt;_

}

Because of this, you cannot lift this text directly from the spreadsheet to a policy editor: you have to select the _\&lt;\&lt;PolicyJson\&gt;\&gt;_ portion for each inline policy. Here is an example inline policy representation. There are four inline policies, and the _\&lt;\&lt;PolicyName\&gt;\&gt;_ values are highlighted:

{
**&quot;GetLogGroupTags-us-west-2&quot;:** {
 &quot;Version&quot;: &quot;2012-10-17&quot;,
 &quot;Statement&quot;: [
 {
 &quot;Action&quot;: [
 &quot;logs:ListTagsLogGroup&quot;
 ],
 &quot;Resource&quot;: &quot;arn:aws:logs:us-west-2:222233334444:log-group:\*&quot;,
 &quot;Effect&quot;: &quot;Allow&quot;,
 &quot;Sid&quot;: &quot;GetLogGroupTags&quot;
 }
 ]
 },
**&quot;GetSSMParameter-us-west-2&quot;:** {
 &quot;Version&quot;: &quot;2012-10-17&quot;,
 &quot;Statement&quot;: [
 {
 &quot;Action&quot;: [
 &quot;ssm:GetParameter&quot;
 ],
 &quot;Resource&quot;: [
 &quot;arn:aws:ssm:us-west-2:222233334444:parameter/SQSQueueParameterStore&quot;
 ],
 &quot;Effect&quot;: &quot;Allow&quot;,
 &quot;Sid&quot;: &quot;GetSSMParameter&quot;
 }
 ]
 },
 **&quot;logstreamer-us-west-2&quot;:** {
 &quot;Version&quot;: &quot;2012-10-17&quot;,
 &quot;Statement&quot;: [
 {
 &quot;Action&quot;: [
 &quot;logs:CreateLogGroup&quot;,
 &quot;logs:CreateLogStream&quot;,
 &quot;logs:PutLogEvents&quot;,
 &quot;logs:ListTagsLogGroup&quot;
 ],
 &quot;Resource&quot;: &quot;arn:aws:logs:us-west-2:222233334444:log-group:/aws/lambda/\*&quot;,
 &quot;Effect&quot;: &quot;Allow&quot;
 },
 {
 &quot;Action&quot;: [
 &quot;sts:AssumeRole&quot;
 ],
 &quot;Resource&quot;: &quot;arn:aws:iam::111122223333:role/LoggingMasterRole-4V4S027YTJMS&quot;,
 &quot;Effect&quot;: &quot;Allow&quot;
 }
 ]
 },
**&quot;SendingtoSQS-us-west-2&quot;:** {
 &quot;Version&quot;: &quot;2012-10-17&quot;,
 &quot;Statement&quot;: [
 {
 &quot;Action&quot;: [
 &quot;sqs:SendMessage&quot;
 ],
 &quot;Resource&quot;: [
 &quot;arn:aws:sqs:us-west-2:111122223333:customer-Centralized-LoggingQueue&quot;,
 &quot;arn:aws:sqs:us-west-2:111122223333:customer-Centralized-CloudtrailLoggingQueue&quot;,
 &quot;arn:aws:sqs:us-west-2:111122223333:customer-Centralized-VPCLoggingQueue&quot;
 ],
 &quot;Effect&quot;: &quot;Allow&quot;,
 &quot;Sid&quot;: &quot;SendingtoSQS&quot;
 }
 ]
 }
 }

# Command Reference

AccessGuard must be invoked as a command-line command.

## IAM &amp; SSO Cataloging and Role Engineering (accessGuard.py)

This is a command executed to gather IAM and SSO entities for role engineering, and write them to the AccessGuard datastore.

**python3 accessGuard.py [-h] --output s3|dynamodb**|_localFilePath_ **[--default-region** _defaultRegionName_**] [--sso-region** _ssoRegionName_**]**

**[--configuration** _s3OrLocalFilePath_**] [--debug]**

- **-h** – Obtain usage information
- **--output** – This is a required option even for –configuration that specifies where output is to be written. You can specify one, two, or all three different output destinations. Valid values are:
  - **s3** – the string &quot;s3&quot; causes results to be written to the Data folder of the S3 bucket from the AgDatastore CloudFormation stack.
  - **dynamodb** -- the string &quot;dynamodb&quot; causes results to be written to the DynamoDB tables created by the AgDatastore CloudFormation stack.
  - _localFilePath_– a valid path on the local file system. This value has no meaning when AccessGuard is invoked as a Lambda, but when invoked as a terminal command it can be any file to which you have write access.
- **--debug** – Request a traceback if the command fails with any exception.
- **--default-region** – the region in which the AgDatastore CloudFormation stack resources are created.
- **--sso-region** – Specify the region in which your SSO instance is defined. The default is us-east-1. SSO is not currently supported in GovCloud, so you should omit this option if you specify a GovCloud partition.
- **--configuration** – specifies a local CSV file or a CSV file stored in an S3 bucket used to configure AccessGuard. The rows of this file are processed and created or updated in a DynamoDB table created by the AgDatastore CloudFormation stack.

### Example

$ **./accessGuard.py -o s3 -o dynamodb -o . --default-region us-gov-west-1**

emit \&lt;module\&gt; 240140i AccessGuard invoked as a command

load Found credentials in environment variables.

emit authorize 220070i assumed role \&lt;\&lt;Role\&gt;\&gt;for service iam

emit processSso 240010w SSO not supported for \&lt;\&lt;Account1\&gt;\&gt;

emit processAccounts 240070i processed account \&lt;\&lt;Account1\&gt;\&gt; adding 16 entities to catalog

emit processSso 240010w SSO not supported for \&lt;\&lt;Account1\&gt;\&gt;

emit processAccounts 240070i processed account \&lt;\&lt;Account1\&gt;\&gt; adding 31 entities to catalog

emit processAccounts 240080i identified 2 similar entities in 2 accounts

emit writeRecords 240040i writing IAM &amp; SSO catalog entries

emit write 220140i writing 48 records to s3 on s3://\&lt;\&lt;Bucket\&gt;\&gt;/Data/accessguard-catalog-\&lt;\&lt;Timestamp\&gt;\&gt;.csv

emit write 220140i writing 47 records to dynamodb on table/\&lt;\&lt;ResultsTable\&gt;\&gt;

emit write 220140i writing 48 records to file on \&lt;\&lt;LocalFilePath\&gt;\&gt;

emit writeRecords 240040i writing similarity entries

emit write 220140i writing 3 records to s3 on s3://\&lt;\&lt;Bucket\&gt;\&gt;/Data/accessguard-similarities-\&lt;\&lt;Timestamp\&gt;\&gt;.csv

emit write 220140i writing 2 records to dynamodb on table/\&lt;\&lt;ResultsTable\&gt;\&gt;

emit write 220140i writing 3 records to file on \&lt;\&lt;LocalFilePath\&gt;\&gt;

emit write 240060i all data written to all output targets

**NOTE:** Output to the DynamoDB tables will have one fewer record because a header record is not required.

**IMPORTANT!** The &quot;assumed role&quot; message for the IAM service is repeated for each account defined in _AWS Accounts &amp; Roles_ sheet; The &quot;assumed role&quot; message for the SSO-ADMIN service is only displayed for the account in which your SSO is defined.