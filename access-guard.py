#! /usr/local/bin/python3
################################################################################
### See README.md
################################################################################

import argparse 
import os
import json
import traceback
import logging
from ..Common import commonClasses as cc
import xlwings as excel

# Lambdas to obtain elements of a botocore ClientError
error = lambda thrown : thrown.get("Error", {}).get("Code", None)
message = lambda thrown : thrown.get("Error", {}).get("Message", None)

# Retrieve the logging instance
logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.INFO)

################################################################################
# 
################################################################################
def labelAccounts ():
    """
    Place account nicknames from the "AWS Accounts & Roles" sheet in columns 2 
    and 3 of the "AD - Permission - Account Map" sheet.
    """
    book = excel.Book.caller()
    inSheet = book.sheets["AWS Accounts & Roles"]
    outSheet = book.sheets["AD - Permission - Account Map"]

    inRow = 3
    inColumn = 2
    outRow = 2
    outColumn = 3

    while True:
        candidate = inSheet.range((inRow, inColumn)).value

        if not candidate:
            break

        outSheet.range((outRow, outColumn)).value = candidate

        inRow += 1
        outColumn += 1
################################################################################
# 
################################################################################
def clearSheet (sheet=None, startRow=3, columns=10, clear=True):
    """
    Clear the contents of the data rows in a spreadsheet. 
    """
    row = startRow

    if clear:
        _LOGGER.info("220w clearing %s ..." % sheet.name)

        while sheet.range((row, 1)).value:
            sheet.range((row, 1), (row, columns)).clear_contents()

            row += 1

    return clear
################################################################################
# 
################################################################################
def processAccounts (srb=None, clear=True):
    """
    Obtain an assumable role from each row of the "AWS Accounts & Roles" sheet, 
    assume that role, then extract IAM entity information using that role, and
    place that information in the "IAM Entities" sheet.
    """
    book = excel.Book.caller()

    labelAccounts()

    # Where information about accounts and roles comes from
    roleSheet = book.sheets["AWS Accounts & Roles"]
    roleRow = 3

    # Where IAM entities will be written
    entitySheet = book.sheets["IAM Entities"]
    entityRow = 3
    clearSheet(entitySheet, entityRow, 9, clear=clear)

    # Where SSO permission set data is written
    setSheet = book.sheets("Permission Sets")
    setRow = 3
    clearSheet(setSheet, setRow, 5, clear=clear)

    # Track similarities between entities
    similar = cc.SimilarEntities()

    # Where similar entries will be written
    similaritySheet = book.sheets["Similar Entities"]
    similarityRow = 3
    clearSheet(similaritySheet, similarityRow, 3, clear=clear)

    # We only need to fetch SSO data once
    fetchedSso = False

    # Now process IAM entities for each 
    while True:
        # Obtain the role information for the current row
        account = cc.AccountRow(
            initializer=roleSheet.range((roleRow, 1), (roleRow, 6)).value,
            srb=srb
        )

        # The SRB may have been replaced
        srb = account.srb

        # Have we hit the end of the account list?
        if not account.accountId:
            break

        # Get IAM entities for this account
        entities = cc.IamActor(
            srb=srb.getServiceRegions("iam"),
            role=account.role, 
            similar=similar
        ).extract()

        # Get a list of row numbers
        rowNumbers = range(entityRow, len(entities)+entityRow)

        # Insert it into the entities sheet
        for rowNumber, row in zip(rowNumbers, entities):
            entitySheet.range((rowNumber, 1)).value = row

        # Only fetch SSO once
        if not srb.isServiced("sso") or not srb.getServiceRegions("sso"):
            _LOGGER.info("230w SSO not supported or no SSO region specified")
        elif not fetchedSso:
            try: 
                sets = cc.SsoActor(
                    srb=srb.getServiceRegions("sso"),
                    role=account.role
                ).permissionSets()

            # Complain about anything other than "access denied"
            except Exception as thrown:
                _LOGGER.info("240s SSO operations %s (%s) returned %s" \
                    % (account.role, srb.getServiceRegions("sso").primaryRegion, str(thrown)))
            
            # Add SSO information to the spreadsheet
            else:
                for _, details in sets.items():
                    inline = details.get("InlinePolicy")
                    display = json.dumps(json.loads(inline), indent=2) if inline \
                        else "-n/a-"

                    row = [
                        details.get("PermissionSetArn"),
                        details.get("Description"),
                        "\n".join(details.get("AttachedManagedPolicies")),
                        display
                    ]

                    setSheet.range((setRow, 1)).value = row
                    setRow += 1

            # Don't repeat the SSO fetch
            fetchedSso = True
    
        # Process next account row
        roleRow += 1

    # Loop through similar entries
    for row in similar.extract():
        if arguments.debug:
            _LOGGER.info("250d similar row %s" % row)

        similaritySheet.range((similarityRow, 1)).value = row
        similarityRow += 1
################################################################################
# 
################################################################################
def lambdaHandler (event=None, context=None):
    """
    Executed when run as a Lambda, which requires an entirely different way of
    processing IAM and SSO because the spreadsheet is not an option.

    The event may pass the following values:
        partition (AWS partition)
        ssoRegion (SSO region if applicable)
        iamRegion (IAM region)
        configurationTable (DynamoDB configuration table ARN)
        outputTable (DynamoDB output table ARN)
        debug (provide more detailed debugging output)
    Items in the configurationTable must be:
        accountId - AWS account number ^([-\d]{12,15})$
        nickname - AWS account nickname 
        partition - AWS partition name (aws, aws-us-gov)
        iamRegion - AWS region name for IAM operations
        ssoRegion - AWS region for SSO operations
    """

    try:
        configuration = cc.DynamoDbActor(event.get("configurationTable"))
        output = cc.DynamoDbActor(event.get("outputTable"))
################################################################################
# 
################################################################################
if __name__ == "__main__":
    """
    Executed when run as a command.
    """
    # Process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--clear", action="store_true",
        default=False, help="Clear existing target sheet contents")
    parser.add_argument("--output-path", required=False, 
        default =".", dest="outputPath", type=str, 
        help="Output path for CSV files")
    parser.add_argument("--partition", required=False,
        default="aws", help="AWS partition (defaults to 'aws')")
    parser.add_argument("--iam-region", dest="iamRegion", required=False, 
        default="us-east-1", help="Region for IAM operations")
    parser.add_argument("--sso-region", dest="ssoRegion", required=False, 
        default=None, help="Region for SSO operations")
    parser.add_argument("--input", required=True,
        type=str, help="CSV file or Excel worksheet on which to act")
    parser.add_argument("--debug", action="store_true", 
        default=False, help="Provide more debugging details")

    arguments = parser.parse_args()
    
    # Determine the file type
    _, extension = os.splitext(arguments.input)
    useCsv = extension.lower() == ".csv"

    # Create a service-region broker
    srb = cc.ServiceRegionBroker(partition=arguments.partition)

    # Add the service region object for IAM
    srb.addServiceRegions(
        supportedRegions=[arguments.iamRegion], 
        service="iam"
    )

    _LOGGER.info("260i IAM operations performed in region %s" %
        arguments.iamRegion)

    # Add the service region for SSO if appropriate
    if arguments.ssoRegion:
        if arguments.partition == "aws-us-gov":
            _LOGGER.warning("270w --sso-region=%s specified for %s partition" %
                (arguments.ssoRegion, arguments.partition))

        srb.addServiceRegions(
            supportedRegions=[arguments.ssoRegion], 
            service="sso"
        )

        if not srb.getServiceRegions("sso").usableRegions:
            raise Exception("280s no SSO regions in partition %s"
                % arguments.partition)

        _LOGGER.info("290i SSO operations performed in region %s" %
            arguments.ssoRegion)

    try:
        # Required xlwings call
        if not useCsv:
            excel.Book(arguments.input).set_mock_caller()

        # Cycle through accounts
        processAccounts(
            srb=srb,
            clear=arguments.clear,
            input=arguments.input,
            outputPath = arguments.outputPath,
            useCsv=useCsv
        )

    # Handle anyhting that goes wrong
    except Exception as thrown:
        _LOGGER.critical("300t terminated with %s" % str(thrown))

        if arguments.debug:
            traceback.print_tb(thrown.__traceback__, limit=5)