# Introduction

## Purpose

[AccessGuard is a multi-account IAM and SSO auditing and role-based
access control (RBAC) engineering tool.]{.ul} Use AccessGuard to produce
an Excel report of all IAM users, groups, roles, and SSO permission sets
for auditors (does not require the auditor to have access to your AWS
environment). AccessGuard also facilitates RBAC role engineering by
detecting similar users, groups, and roles and allowing comparison with
SSO permission sets to produce a minimum set of well-engineering RBAC
roles. AccessGuard uses the xlwings Python module to populate an Excel
role engineering spreadsheet as follows:

-   Enumerate existing AWS IAM entities (users, groups, and roles)

-   Enumerate existing SSO permission sets

-   Identify similar IAM users, groups, and roles based on similar
    managed policies and similar membership (for groups)

***IMPORTANT!*** Remember to distinguish between IAM roles and RBAC
roles. RBAC roles may correspond to IAM roles, IAM groups, or SSO
permission sets. An RBAC role is a functional role, whereas an IAM role
is a permissions role.

## Installation & Operation

AccessGuard has been tested on Unix-like operating systems such as MacOS
and Linux. It may work on suitably configured Windows operating systems,
but this has not been tested.

1.  The following are REQUIRED:

    1.  Python 3.6 or greater

    2.  AWS boto3 SDK

    3.  AWS command line interface (CLI)

    4.  Xlwings (**pip3 install xlwings**)

2.  Populate the *AWS Accounts & Roles* sheet of **access-guard.xlsm**
    with the following information:

    1.  The AWS account number

    2.  A nickname for the AWS account

    3.  An assumable role to use for that account

3.  Open a terminal window and change to the directory containing
    **access-guard.py**

4.  Authorize your terminal window to AWS. The credentials you use may
    be obtained from a service such as AWS Isengard, or configured using
    the aws config command, or by any other means that gives you
    sufficient authority to assume the roles specified in (2) above.

5.  Execute **python3 access-guard.py
    --sso-region=**[\<\<SsoRegion\>\>]{.smallcaps}
    **--iam-region[=]{.smallcaps}**[\<\<IamRegion\>\>]{.smallcaps} where
    [\<\<IamRegion\>\>]{.smallcaps} is any region in which you operate
    AWS resources, and [\<\<SsoRegion\>\>]{.smallcaps} is the region in
    which your AWS Single Sign-On instance resides.

6.  Accept the Excel prompt to *Enable macros*

## Process Description

The AccessGuard Python program reads account and assumable role
information from, and writes its results to, the AccessGuard
spreadsheet.

1.  **Multi Account Support --** the assumable role for *[each]{.ul}*
    account listed in the *AWS Accounts & Roles* sheet is assumed (if
    there is no assumable role, credentials are inherited from your
    environment or your AWS configuration file).

2.  IAM users, groups, and roles are enumerated, as well as the managed
    policies attached to each, and any inline policies in JSON format.
    The result is written to the *IAM Entities* sheet as follows:

    1.  Column A - IAM user, group, or role name

    2.  Column B - The associated AWS account number

    3.  Column C - The type of entity (user, group, or role)

    4.  Column D - For groups only, a list of current members

    5.  Column E - A list of managed policy names

    6.  Column F - Inline policies in JSON format (see note below)

3.  If there is an SSO instance in the current account, SSO permission
    sets and their attributes are enumerated. The results are written to
    the *Permission Sets* sheet as follows:

    1.  Column A -- Permission set ARN

    2.  Column B -- Permission set description

    3.  Column C -- AWS managed policy names associated with the
        permission set

    4.  Column D -- Inline policies associated with the permission set
        (JSON format)

4.  Once (2) and (3) are completed, IAM users, groups, and roles are
    analyzed to identify similar entities based on managed policies
    (users, groups, and roles) and group membership (groups only). The
    results are written to the *Similar Entities* sheet as follows:

    1.  Column A -- Criterion by which the entities are similar
        ("Managed Policies" or "Group Membership")

    2.  Column B -- Similar items (a list of managed policies or a list
        of group members, based on column A)

    3.  Column C -- List of similar entities (all the entities that
        share the items listed in column B)

> The *Similar Entities* sheet can be used to identify unnecessary
> users, roles, and groups that have the same set of managed policies,
> and unnecessary groups that have the same group membership. It is not
> necessarily the case that all similar entities are unnecessary---that
> is a judgement that must be made by the customer and the customer's
> AWS ProServe team.

AccessGuard may take several minutes to complete. Refer to the terminal
window you opened in the installation section above for debugging and
error messages.

## Inline Policies in the IAM Entities Sheet

Because multiple inline policies may be associated with an IAM entity,
each policy is presented in an associative structure (dict, hash) as
follows:

{

*[\<\<PolicyName\>\>]{.smallcaps}*: *[\<\<PolicyJson\>\>]{.smallcaps}*

}

Because of this, you cannot lift this text directly from the spreadsheet
to a policy editor: you have to select the
*[\<\<PolicyJson\>\>]{.smallcaps}* portion for each inline policy. Here
is an example inline policy representation. There are four inline
policies, and the *[\<\<PolicyName\>\>]{.smallcaps}* values are
highlighted:

{\
**\"GetLogGroupTags-us-west-2\":** {\
\"Version\": \"2012-10-17\",\
\"Statement\": \[\
{\
\"Action\": \[\
\"logs:ListTagsLogGroup\"\
\],\
\"Resource\": \"arn:aws:logs:us-west-2:775794577280:log-group:\*\",\
\"Effect\": \"Allow\",\
\"Sid\": \"GetLogGroupTags\"\
}\
\]\
},\
**\"GetSSMParameter-us-west-2\":** {\
\"Version\": \"2012-10-17\",\
\"Statement\": \[\
{\
\"Action\": \[\
\"ssm:GetParameter\"\
\],\
\"Resource\": \[\
\"arn:aws:ssm:us-west-2:775794577280:parameter/SQSQueueParameterStore\"\
\],\
\"Effect\": \"Allow\",\
\"Sid\": \"GetSSMParameter\"\
}\
\]\
},\
**\"logstreamer-us-west-2\":** {\
\"Version\": \"2012-10-17\",\
\"Statement\": \[\
{\
\"Action\": \[\
\"logs:CreateLogGroup\",\
\"logs:CreateLogStream\",\
\"logs:PutLogEvents\",\
\"logs:ListTagsLogGroup\"\
\],\
\"Resource\":
\"arn:aws:logs:us-west-2:775794577280:log-group:/aws/lambda/\*\",\
\"Effect\": \"Allow\"\
},\
{\
\"Action\": \[\
\"sts:AssumeRole\"\
\],\
\"Resource\":
\"arn:aws:iam::563388986931:role/au-logging-primary-LoggingMasterRole-4V4S027YTJMS\",\
\"Effect\": \"Allow\"\
}\
\]\
},\
**\"SendingtoSQS-us-west-2\":** {\
\"Version\": \"2012-10-17\",\
\"Statement\": \[\
{\
\"Action\": \[\
\"sqs:SendMessage\"\
\],\
\"Resource\": \[\
\"arn:aws:sqs:us-west-2:563388986931:AU-Centralized-LoggingQueue\",\
\"arn:aws:sqs:us-west-2:563388986931:AU-Centralized-CloudtrailLoggingQueue\",\
\"arn:aws:sqs:us-west-2:563388986931:AU-Centralized-VPCLoggingQueue\"\
\],\
\"Effect\": \"Allow\",\
\"Sid\": \"SendingtoSQS\"\
}\
\]\
}\
}

# AccessGuard Spreadsheet Guide

AccessGuard reads account information from the AccessGuard spreadsheet,
and writes results to the AccessGuard spreadsheet. This section
describes the formats of the various sections.

## "IAM Entities" Sheet

The following columns are written by AccessGuard to the *IAM Entities*
sheet. The column names specified in **grey** are filled in by the
AccessGuard program. The column names specified in **black** are
supplied by you, the role engineer.

  Column Name                      Description                                  Notes
  -------------------------------- -------------------------------------------- ------------------------------------------------
  IAM User, Group, or Role Name    The name of the IAM entity                   This is the name only, not the ARN
  Account                          The account number for the entity            \--
  Type (User, Group, Role)         The type of the IAM entity                   "User," "Group," or "Role"
  Current Members                  The current member list for an IAM group     \--
  Managed Policy Names             A list of managed IAM policies names         One policy name per line
  Inline Policy Documents (JSON)   All inline policy documents in JSON format   Structured keyed by policy document name
  Action (Keep, Migrate, Delete)   Your desired action for this entity          "Keep," "Migrate," or "Delete"[^1]
  Target Permission Set            The target SSO permission set name           Specify for a migration action to SSO
  New Members                      The new target members for a group           Specify for a migration action to a. new group

The following screen shot is an example of the IAM Entities sheet.

![](media/image1.png){width="7.19672353455818in"
height="4.965517279090114in"}

## "Permission Sets" Sheet

The following columns in **grey** are written by AccessGuard to the
Permission Sets sheet. These columns describe existing SSO permission
sets. The last column in **black** described below is not written by
AccessGuard, but is available for you to specify changes targeted for a
given permission set.

  Column Name                      Description                                                                       Notes
  -------------------------------- --------------------------------------------------------------------------------- -------------------------------------------------------------------------
  Permission Set ARN               The ARN of the SSO permission set                                                 \--
  Permission Set Description       The text description of the permission set                                        This is specified when you create the permission set, and may be blank.
  AWS Managed Policy Names         A list of AWS managed policies                                                    \--
  Inline Policies (JSON)           A JSON object describing any inline policies associated with the permission set   \--
  Target AWS Service Permissions   A user-specified set of changes to the permission set                             \--

## "Similar Entities" Sheet

The following columns are written by AccessGuard to the *Similar
Entities* sheet. This sheet describes users, groups, and roles that
appear similar. This sheet can be used to identify redundant entities,
entities with excessive privileges, etc.

  Column Name           Description                                           Notes
  --------------------- ----------------------------------------------------- --------------------------------------------------------------------------------------------
  Similar By            The way in which the entities are similar             "Managed Policies" or "Group Membership"
  Similar Item List     The items that are similar for these entities         Managed policy names or group members
  Similar Entity List   A list of entities that share the similar item list   The ARNs of similar entities, sorted by the entity name, the account, and the entity type.

The following screen shot is an example of the Similar Entities sheet.

![](media/image2.png){width="7.344827209098862in"
height="5.0648709536307965in"}

## "AWS Accounts & Roles" Sheet

The *AWS Accounts & Roles* sheet is a data source sheet -- you fill in
these values *[before]{.ul}* running AccessGuard. This sheet contains
AWS account IDs, account nicknames, and assumable roles read by
AccessGuard to enumerate IAM entities. The role engineer fills out these
values, which are used as input to AccessGuard.

  Column Name        Description                     Notes
  ------------------ ------------------------------- -----------------------------------------
  Account ID         The AWS account ID              Can contain dashes, e.g. 1111-2222-3333
  Account Nickname   An arbitrary account nickname   This can be whatever you wish
  Role ARN           An assumable role ARN           \--

# Command Reference

AccessGuard must be invoked as a command-line command.

## Gather Information for Role Engineering (access-guard.py)

This is a command executed to gather IAM entities for role engineering,
and write them to the AccessGuard spreadsheet.

**python3 access-guard.py** \[**-h**\] \[**\--input**
*[\<\<SpreadSheet\>\>]{.smallcaps}*\] \[**\--debug**\]
\[**\--iam-region** *[\<\<IamRegion\>\>]{.smallcaps}*\]
\[**\--sso-region** *[\<\<SsoRegion\>\>]{.smallcaps}*\]

\[**\--clear**\]

-   **-h** -- Obtain usage information

-   **\--input** -- If the AccessGuard spreadsheet is in a different
    directory than the executable, or has a different name than the
    default, you can specify the spreadsheet location using this option
    and *[\<\<SpreadSheet\>\>]{.smallcaps}*. The default is
    access-guard.xlsm.

-   **\--debug** -- Request a traceback if the command fails with any
    exception.

-   **\--clear** -- Delete existing data in the *IAM Entities*,
    *Permission Sets*, and *Similar Entities* sheets (the default is not
    to clear the data)

-   **\--iam-region** -- Specify the region in which the IAM operations
    are to take place. Since IAM is a global service this can be any
    region in which you have AWS assets. The default is us-east-1.

-   **\--sso-region** -- Specify the region in which your SSO instance
    is defined. The default is us-east-1.

### Important Notes

-   The input spreadsheet ...

    -   Must exist

    -   Must be authorized to execute macros

    -   Must contain the following sheet names:

        -   [IAM
            Entities](file:///Users/nandrob/Google%20Drive/n24289@gmail.com/Work/GitHub/rescor.nmillc.net/IAM_Entities#_)

        -   [Permission
            Sets](file:///Users/nandrob/Google%20Drive/n24289@gmail.com/Work/GitHub/rescor.nmillc.net/Permission_Sets#_)

        -   [Similar
            Entities](file:///Users/nandrob/Google%20Drive/n24289@gmail.com/Work/GitHub/rescor.nmillc.net/Similar_Entities#_)

        -   [AWS Accounts &
            Roles](file:///Users/nandrob/Google%20Drive/n24289@gmail.com/Work/GitHub/rescor.nmillc.net/AWS_Accounts_&#_)

    -   Each sheet must contain ...

        -   A sheet title in cell A1

        -   Column headers in row 2

        -   All the columns described in the [AccessGuard SpreadSheet
            Guide](#accessguard-spreadsheet-guide) above

### Example

<code>
$ **python3 access-guard.py --iam-region=us-west-2
--sso-region=us-east-1 --clear**<br>
(i) IAM operating on region us-west-2<br>
(i) SSO operating on region us-east-1<br>
(w) clearing IAM Entities ...<br>
(w) clearing Permission Sets ...<br>
(w) clearing Similar Entities ...<br>
(i) assumed role [_Role_]{.smallcaps} for service iam<br>
(i) assumed role [_Role_]{.smallcaps} for service sso-admin<br>
</code>

**IMPORTANT!** The "assumed role" message for the IAM service is
repeated for each account defined in *AWS Accounts & Roles* sheet; The
"assumed role" message for the SSO-ADMIN service is only displayed for
the account in which your SSO is defined.

[^1]: "Keep" indicates the entity will be retained as-is; "Delete" means
    the entity will be deleted and not replaced; "Migrate" means the
    entity will be retained with changes described elsewhere.
