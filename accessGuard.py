#! /usr/local/bin/python3
################################################################################
### See README.md
################################################################################

import argparse
import enum 
#import os
import json
import traceback
import logging
import commonClasses as cc
import accessGuardClasses as agc
import re
import csv
#import sys
import pprint
import boto3
import datetime
import hashlib

# Lambdas to obtain elements of a botocore ClientError
error = lambda thrown : thrown.get("Error", {}).get("Code", None)
message = lambda thrown : thrown.get("Error", {}).get("Message", None)

# Retrieve the logging instance
logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.INFO)

# Contains SSM parameter configuration
_PARAMETERS =  re.sub(r'[\s\n]+', " ", """
    {
        "prefix": "/AccessGuard",
        "templates": { 
          "configurationTable": "%s/ConfigurationTableArn",
          "resultsTable": "%s/ResultsTableArn",
          "similarityTable": "%s/SimilarityTableArn",
          "bucket": "%s/Bucket",
          "code": "%s/CodeFolder",
          "data": "%s/DataFolder"
        }
      }
  """).strip()

# Define options 
cc.OptionsObject._PROPERTIES = [
    cc.OptionDescriptor("ssoRegion", None, None),
    cc.OptionDescriptor("defaultRegion", None, None),
    cc.OptionDescriptor("debug", False, None),
    cc.OptionDescriptor("output", None, None),
    cc.OptionDescriptor("configuration", None, None)
  ]
################################################################################
# 
################################################################################
def processIam (reportDate=None, account=None, results=[], similar=None):
  """
  Process IAM entities
  """
  # Obtain IAM entities
  entities = \
    agc.IamActor(role=account.role, region=account.defaultRegion, 
    similar=similar).extract(format=dict)

  # Process each IAM entity
  for entity in entities:
    result =agc.IamOutputRow(name=entity["name"], account=entity["account"], 
      ugr=entity["type"], members=entity["members"], managed=entity["managed"],
      policy=entity["policy"], reportDate=reportDate)

    results.append(result)

  return results
################################################################################
# 
################################################################################
def ssoIsSupported (partition=None):
  """
  Return True if SSO is supported in this partition
  """
  ssoRegions = boto3.session.Session().get_available_regions(service_name="sso",
    partition_name=partition)

  return ssoRegions
################################################################################
# 
################################################################################
def processSso (reportDate=None, account=None, results=[], similar=None):
  """
  Process SSO permission sets 
  """
  # Report if not supported
  if not ssoIsSupported(account.partition):
    cc.emit("240010", "w", f'SSO not supported for {account.accountId}')

  # Report if no SSO region specified
  elif not account.ssoRegion:
    cc.emit("240020", "w", f'No SSO region specified for {account.accountId}')

  # List permission sets
  else:
    try:
      sets = agc.SsoActor(region=account.ssoRegion, role=account.role)\
        .permissionSets()

    # Complain but do not abort if there is an error
    except Exception as thrown:
      type = thrown.__class__.__name__
      cc.emit("240030", "e", f'*** SSO operation raised {type}: {thrown}')

    # Process SSO entites
    else:
      for details in sets.values():
        inline = details.get("InlinePolicy")
        policies = json.loads(inline) if inline else {}
        arn = details.get("PermissionSetArn")
        name = arn.split(":")[5]
        managed = details.get("AttachedManagedPolicies")

        result = agc.IamOutputRow(name=name, account=account.accountId, 
          ugr="permission-set", managed=managed, policy=policies, arn=arn,
          description=details.get("Description"), reportDate=reportDate)

        results.append(result)

  return results
################################################################################
# 
################################################################################
class OutputBroker:
  """
  This class directs a set of results to a given output stream, which can be
  DynamoDb (tables are fixed), S3 (bucket and folder are fixed), or a local
  file (can be wherever)
  """
  def __init__ (self, streams=None, dataSource=None, reportDate=None, 
    parameters=None, catalogEntries=None, similarityEntries=None):
    """
    """
    self.streams = streams
    self.dataSource = dataSource
    self.reportDate = reportDate
    self.parameters = parameters
    self.catalogEntries = catalogEntries
    self.similarityEntries = similarityEntries 
    self.catalog = {}
    self.similarity = {}

    for stream in streams:
      self.catalog[stream] = self.catalogPaths(stream)
      self.similarity[stream] = self.similarityPaths(stream)
  #-----------------------------------------------------------------------------
  def catalogPaths (self, stream):
    if stream.lower() == "s3":
      stream = stream.lower()
      bucket = self.parameters.bucket
      key = self.parameters.data + "/accessguard-catalog-" + self.reportDate + ".csv"
      format = list
      path = f's3://{bucket}/{key}'
    elif stream.lower() == "dynamodb":
      stream = stream.lower()
      bucket = None
      key = None
      format = dict
      path = self.parameters.resultsTable
    else:
      bucket = None
      key = None
      format = list
      path = stream + "/accessguard-catalog-" + self.reportDate + ".csv"

    return (stream, format, bucket, key, path)
  #-----------------------------------------------------------------------------
  def similarityPaths (self, stream):
    if stream.lower() == "s3":
      stream = stream.lower()
      bucket = self.parameters.bucket
      key = self.parameters.data + "/accessguard-similarities-" + self.reportDate + ".csv"
      format = list
      path = f's3://{bucket}/{key}'
    elif stream.lower() == "dynamodb":
      stream = stream.lower()
      bucket = None
      key = None
      format = dict
      path = self.parameters.similarityTable
    else:
      bucket = None
      key = None
      format = list
      path = stream + "/accessguard-similarities-" + self.reportDate + ".csv" 

    return (stream, format, bucket, key, path)
  #---------------------------------------------------------------------------
  def writeRecords (self, description=None, targets={}, results=[]):
    """
    Write a set of records to an output stream
    """
    cc.emit("240040", "i", f'writing {description} entries')

    for streamId in self.streams:
      _, format, _, _, path = targets[streamId]

      if format == dict:
        records = \
          [result.asDict(ttl=86400*365.25/4) for result in results]
      else:
        records = \
          [results[0].asList(header=True)] + \
          [result.asList() for result in results]

      self.dataSource.write(path, records=records)

      cc.emit("240050", "i", 
        f'wrote {len(records)} {description} entries to {path}')

    return self
  #---------------------------------------------------------------------------
  def write (self):
    """
    Run through the streams and write the results wherever the user 
    requests
    """
    
    self.writeRecords("IAM & SSO catalog", self.catalog, self.catalogEntries)
    self.writeRecords("similarity", self.similarity, self.similarityEntries)

    cc.emit("240060", "i", "all data written to all output targets")

    return self
################################################################################
# 
################################################################################
def processAccounts (options=None):
  """
  Obtain an assumable role from account (if any), assume that role, then 
  extract IAM entity information from that account.
  """
  # Generate a report date
  reportDate = datetime.datetime.now().isoformat()

  # Data source client
  client = cc.DataSource(s3Region=options.defaultRegion, 
    dynamoRegion=options.defaultRegion)

  # Obtain configuration
  parameters = cc.SsmActor(configuration=_PARAMETERS, 
    region=options.defaultRegion)
  table = parameters.configurationTable
  configuration = client.read(table)
  results = []
  accounts = 0
  count = 0

  # Process each account successively
  for record in configuration:
    if isinstance(record, dict):
      keys = [ 'accountId', 'nickname', 'role', 'partition', 'defaultRegion', 'ssoRegion']
      candidate = []

      for key in keys:
        candidate.append(record.get(key))
    else:
      candidate = record

    account = agc.AccountRow(candidate)
    similar = agc.SimilarEntities()

    # Get IAM entities
    results = processIam(reportDate, account, results, similar)
      
    # Get SSO entities
    results = processSso(reportDate, account, results, similar)

    # Annotate progress
    added = len(results) - count
    count += added
    accounts += 1

    cc.emit("240070", "i", f'proccessed account {account.accountId} ' + 
      f'adding {added} entities to catalog')
      
  # Extract similar items
  similarities = similar.extract(format=dict)
  items = []

  # See what similarities exist
  for similarity in similarities:
    item = agc.SimilarityOutputRow(reportDate=reportDate,
      similarity=similarity["similarity"], by=similarity["by"],
      entities=similarity["entities"])

    items.append(item)

  cc.emit("240080", "i", f'identified {len(items)} similar entities ' + 
    f'in {accounts} accounts')

  # Write results 
  writer = OutputBroker(options.output, dataSource=client, 
    reportDate=reportDate, parameters=parameters, catalogEntries=results, 
    similarityEntries=items).write()

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
        defaultRegion (default region)
        configurationTable (DynamoDB configuration table ARN)
        outputTable (DynamoDB output table ARN)
        debug (provide more detailed debugging output)
    Items in the configurationTable must be:
        accountId - AWS account number ^([-\d]{12,15})$
        nickname - AWS account nickname 
        partition - AWS partition name (aws, aws-us-gov)
        defaultRegion - AWS default region name for all services
        ssoRegion - AWS region for SSO operations
    """
    cc.emit("240090", "i", 
      f'AccessGuard invoked as a Lambda\n{pprint.pformat(event)}')

    options = cc.OptionsObject(event=event)

    if options.configuration:
      configure(options)
    else:
      cc.emit("240100", "d", f'SSO operations performed in {options.ssoRegion}')

      try:
        # Cycle through accounts
        processAccounts(options=options)

      # Handle anyhting that goes wrong
      except Exception as thrown:
        cc.emit("240110", "t", 
          f'terminated with {thrown.__class__.__name__}: {thrown}')

        if event.get("debug", False):
          traceback.print_tb(thrown.__traceback__, limit=5)
################################################################################
# 
################################################################################
def configure (options=None):
  """
  Read from a CSV file and store results in the configuration table
  """

  # Map some SSM parameteres
  parameters = cc.SsmActor(configuration=_PARAMETERS, 
    region=options.defaultRegion)
  table = parameters.configurationTable

  # Allow us to read and write S3, DynamoDb, and local files
  fileClient = cc.DataSource(s3Region=options.defaultRegion)

  # Read the configuration from the data source, which must be a file containing
  # rows of six fields in CSV format
  rows = fileClient.read(path=options.configuration)

  # Parse the CSV
  reader = csv.reader(rows)
  records = []

  for line, row in enumerate(reader):
    if not row:
      cc.emit("240112", "w", f'empty configuration row at line {line+1}')
    elif not re.match(r'^\d{12}$', row[0]):
      cc.emit("240114", "w", f'row {line+1} skipped as a header row: {row}')
    else:
      records.append(agc.AccountRow(row))

  # Flush the table of matching entries
  source, client, path, bucket, key = fileClient.discriminate(path=table)

  for record in records:
    accountId = record.accountId 
    response = fileClient.clients\
      .get("dynamodb")\
      .get(parameters.configurationTable)\
      .table.delete_item(Key={"accountId": accountId})

    cc.emit("240120", "d", f'deleted item for {accountId} ' 
      + f'response {response.get("ResponseMetadata", {}).get("HTTPStatusCode")}')

  # Write to the configuration table (this will result in multiple entries if
  # configure is run more than once--you must manually flush the table before
  # configuring a second or subsequent time)
  count = fileClient.write(path=table, records=[row.record() for row in records])

  cc.emit("240130", "i", f'wrote {count} items to {fileClient.parseArn(table)}')
################################################################################
# 
################################################################################
if __name__ == "__main__":
    """
    Executed when run as a command.
    """
    cc.emit("240140", "i", f'AccessGuard invoked as a command')

    # Process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "-o", required=True, 
        action="append", dest="output",
        type=str, help="Local file path, 's3', or 'dynamodb' for output")
    parser.add_argument("--default-region", "-r", dest="defaultRegion",
        default=None, help="Default region to use where a region is needed")
    parser.add_argument("--sso-region", "-s", dest="ssoRegion",  
        default=None, help="Region for SSO operations")
    parser.add_argument("--configuration", "-c", type=str, 
        help="Local path or S3 path containing initialization CSV")
    parser.add_argument("--debug", "-d", action="store_true", 
        default=False, help="Provide more debugging details")

    arguments = parser.parse_args()
    
    options = cc.OptionsObject(arguments=arguments)

    if options.configuration:
      configure(options)
    else:
      cc.emit("240150", "d", f'SSO operations performed in {options.ssoRegion}')

      try:
        # Cycle through accounts
        processAccounts(options=options)

      # Handle anyhting that goes wrong
      except Exception as thrown:
        cc.emit("240160", "t", 
          f'terminated with {thrown.__class__.__name__}: {thrown}')

        if arguments.debug:
          traceback.print_tb(thrown.__traceback__, limit=5)
