#!/usr/local/bin/python3
################################################################################
# 
################################################################################
from json.decoder import JSONDecodeError
import logging
import os
from typing import Dict
import boto3
from boto3 import session
import botocore.exceptions
import botocore
import re
import pprint
import json
from datetime import date, datetime
import time
from boto3.dynamodb.conditions import Key
from decimal import Decimal
import random
import uuid
import sys
import csv
import io

# Global debugging flag
_DEBUGGING = False

# Default region list
_DEFAULT_REGION_LIST = \
  os.environ.get("AdrDefaultRegions", ["us-east-1", "us-east-2"])

# The partition in which we will operate
_DEFAULT_PARTITION = os.environ.get("AdrDefaultPartition", "aws")

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(funcName)s %(message)s")
_LOGGER = logging.getLogger()
_LOGGER.setLevel(logging.INFO)
################################################################################
# 
################################################################################
def emit (messageNumber=None, severity="i", message=None):
  """
  Display a logging message with a unique identifying number
  """
  loggerTable = {
    "d" : _LOGGER.info,
    "i" : _LOGGER.info,
    "w" : _LOGGER.warning,
    "e" : _LOGGER.error,
    "s" : _LOGGER.critical,
    "t" : _LOGGER.critical,
    "*" : _LOGGER.info
  }

  # Format the message number
  number = "%06d" % int(float(messageNumber))

  # Calling function
  function = sys._getframe(1).f_code.co_name

  # Obtain the logger based on logging level
  logger = loggerTable.get(severity) if severity in loggerTable \
    else loggerTable.get("*")

  # Emit non-debug messages, or debug messages if --debug is set
  if (severity != "d") or _DEBUGGING:
    logger(f'{function} {number}{severity} {message}')
################################################################################
#
################################################################################
class ActorException (Exception):
    pass
################################################################################
#
################################################################################
class Actor:
    """
    Abstract class for AWS API functions. The class defines a service client
    and a set of actions to be carried out with that client.
    """
    # Regions supported by default 
    _REGIONS = _DEFAULT_REGION_LIST
    #---------------------------------------------------------------------------
    def __init__ (self, partition=_DEFAULT_PARTITION, 
      region=_DEFAULT_REGION_LIST[0], service=None, role=None,
      clientFactory=None):
      """ See the class definition for details. """
      self.clientFactory = self.botoClient if clientFactory is None \
        else clientFactory
      self.service = service  
      self.partition = partition
      self.region = region
      self.role = role
      self.authorized = False
      self.accessKeyId = None
      self.accessKey = None
      self.sessionToken = None
      self.client = None
      self.principal = None

      # Get authorization
      self.authorize()

      # Set the account ID
      self.accountId = self.principal.get("Account") if not self.role\
        else self.role.split(":")[4]

      # Get the client
      self.client = self.getClient()
    #---------------------------------------------------------------------------
    def botoClient (self, **parameters):
      """
      A client factory that uses boto3.client API to create a client
      """
      return boto3.client(self.service, **parameters)
    #---------------------------------------------------------------------------
    def getClient (self, overFactory=None):
      """
      Create an AWS API client associated with a specific region
      """
      try:
          factory = self.clientFactory if not callable(overFactory) \
            else overFactory

          client = factory(
              aws_access_key_id=self.accessKeyId, 
              aws_secret_access_key=self.accessKey,
              aws_session_token=self.sessionToken ,
              region_name=self.region             
          )

          emit("220010", "d", 
            f'created {self.service} client in {self.region} using {factory}')

      except Exception as thrown:
          emit("220020", "s", "error obtaining client for %s in %s: %s" % \
              (self.service, self.region, str(thrown)))
          
          raise thrown

      return client
    #---------------------------------------------------------------------------
    def authorize (self):
      """
      If no role is supplied to the actor, the authorization is implicit
      through the credentials already in the environment. Otherwise, use
      sts:assume_role to gain the privileges associated with the supplied
      role ARN.
      """
      emit("220030", "d", "authorize %s client region %s partition %s"
          % (self.service, self.region, self.partition))

      configuration = botocore.config.Config(region_name=self.region)
      client = boto3.client("sts", config=configuration)

      emit("220040", "d", "obtained STS client %s" % client)

      if not self.role:
          emit("220050", "d", "using environment credentials for %s" \
              % self.service)
          self.authorized = True
      else:
          try:
              answer = client.assume_role(
                  RoleArn=self.role, 
                  RoleSessionName=("%s-access" % self.service)
              )

              emit("220060", "d", "sts:assume_role returned %s" % (answer))

              self.accessKeyId = answer["Credentials"]["AccessKeyId"]
              self.accessKey = answer["Credentials"]["SecretAccessKey"]
              self.sessionToken = answer["Credentials"]["SessionToken"]
              self.authorized = True

              emit("220070", "i", "assumed role %s for service %s" \
                  % (self.role, self.service))

          except Exception as thrown:
              emit("220080", "s", "Cannot assume role: %s" % str(thrown))

              self.authorized = False

      try:
        self.principal = client.get_caller_identity()
      except botocore.exceptions.ClientError as thrown:
        errorDetails = thrown.response.get("Error", {})
        code = errorDetails.get("Code")

        if not(code in ["InvalidClientTokenId", "ExpiredToken"]):
          raise thrown
        else:
          raise ActorException(f'refresh credentials ({code})')
      except Exception as thrown:
          emit("220090", "s", "sts:get_caller_identity failed: %s" \
              % str(thrown))
            
          raise thrown

      return self
    #---------------------------------------------------------------------------
    def page (self, api=None, fence=None, additional={}, maxResults=100,
      eyeCatcher="NextToken"):
      """
      Process an API call that may return results in multiple "pages" 
      separated by a NextToken value. 
      """
      token = None
      answer = []

      while True:
          if token:
              base = {eyeCatcher: token}
          else:
              base = {}

          if maxResults and re.search("^\d+$", str(maxResults)):
              base["MaxResults"] = maxResults

          parameters = {**base, **additional}

          response = api(**parameters)
          token = response.get(eyeCatcher, None)
          values = response.get(fence, [])

          answer += values

          if not token:
              break

      return answer
################################################################################
# 
################################################################################
class S3Actor(Actor):
    """
    Perform AWS Simple Storage Service (S3) API operations. The following S3
    API operations are used by this concrete class:

    s3:PutObject
    s3:GetObject
    """
    _PREFIX = "s3Actor"
    _SUFFIX = ".csv"
    _FOLDER = "s3Objects"
    #---------------------------------------------------------------------------
    def __init__ (self, bucket=None, folder=_FOLDER, prefix=_PREFIX, 
        suffix=_SUFFIX, region=None, role=None):
        """
        See the class definition for details
        """
        super().__init__(service="s3", region=region, role=role)

        self.prefix = prefix
        self.suffix = suffix
        self.folder = folder 
        self.bucket = bucket
        self._filename = None
    #---------------------------------------------------------------------------
    def buildFilename (self=None, bucket=None, folder=None, name=None, 
        extension=None):
        """
        Construct an fully qualified S3 name from the bucket, folder, 
        filename, and extention.
        """
        answer = (bucket if bucket else self.bucket) + "/" + \
            (folder if folder else self.folder) + "/" + \
            ((name + "." + extension) if extension else name)

        return answer
    #---------------------------------------------------------------------------
    @property
    def filename (self):
        """
        Return the unique S3 key associated with this object.
        """
        if self._filename:
            answer = self._filename
        else:
            answer = self.prefix + "-" + \
                time.strftime("%Y%m%d-%H%M%S") + \
                self.suffix

            self._filename = answer

        return answer
    #---------------------------------------------------------------------------
    def filePath (self, directory = "/tmp"):
        """
        Return a local fully qualified file path.
        """
        return "/".join([directory, self.filename])
    #---------------------------------------------------------------------------
    @property
    def objectKey (self):
        """
        Return an S3 object key from the "folder" and unique filename.
        """
        return "/".join([self.folder, self.filename]) 
    #---------------------------------------------------------------------------
    def put (self, inputFile = None, body=None, outputObject = None ):
        """
        Store an object in the S3 bucket. The inputFile is read from
        the local filesystem and stored to S3 as outputObject.
        """
        target = outputObject if outputObject else self.objectKey

        try:
          if body:
            answer = self.client.put_object(Bucket=self.bucket, Key=target,
              Body=body)
          else: 
            source = inputFile if inputFile else self.filePath()

            with open(source, "rb") as source:
                answer = self.client.put_object(Bucket=self.bucket, Key=target,
                  Body=source)

        except botocore.exceptions.ClientError as thrown:
            answer = None
            emit("220100", "s", 
              f'cannot put object {target} to bucket {self.bucket}: {thrown}')

        return answer
    #---------------------------------------------------------------------------
    @classmethod
    def parseS3Url (className, url=None):
        """
        Parse an S3 url into bucket and key components.
        """
        # This pattern will match s3://[bucket]/[key]
        pattern = re.compile(r'^s3://([-\w\.]+)/(.*)', flags=re.IGNORECASE)

        # Perform the match
        match = pattern.match(url) if url else None

        if not match:
            answer = None
        else:
            answer = ( match.group(1), match.group(2) )

        return answer
    #---------------------------------------------------------------------------
    def get (self=None, file=None, bucket=None, key=None, split=False):
        """
        Retrieve an object from S3 or a local file and return the entire body.

        Parameters
        ----------
        file : str 
            A local file path 
        bucket : str
            Mutually exclusive with file, specifies an S3 bucket name
        key : str
            Mutually exclusive with file, specifies an S3 object key
        """
        # Specifying a local file overrides S3
        if file:
            source = file

            try:
                with open(source, "r") as input:
                    candidate = input.read()

                if not split:
                    answer = candidate
                else:
                    answer = [ line.strip() for line in candidate.splitlines() ]
            except Exception as thrown:
                answer = None
                cc.emit("220110", "s", f'cannot read file {source}: {thrown}')
        else:
            bucket = bucket if bucket else self.bucket
            key = key if key else self.objectKey

            try:
                response = self.client.get_object(
                    Bucket=bucket,
                    Key=key
                )

                candidate = response.get("Body").read().decode("utf-8")

                if not split:
                    answer = candidate
                else:
                    answer = [ line.strip() for line in candidate.splitlines() ]
            except botocore.exceptions.ClientError as thrown:
                answer = None
                cc.emit("220120", "s", f'cannot get s3://{bucket}/{key}: {thrown}')

        return answer   
################################################################################
# 
################################################################################
class DataSource:
  """
  An interface for reading and writing S3 objects, local files, and DynamoDb
  tables.
  """
  _S3 = "s3"
  _DYNAMODB = "dynamodb"
  _FILE = "file"
  #-----------------------------------------------------------------------------
  def __init__ (self, s3Region=None, dynamoRegion=None):
    """ See class definition for details """
    self.stringIo = io.StringIO()
    self.s3Region = s3Region
    self.dynamoRegion = dynamoRegion
    self.clients = {
      self._S3: {},
      self._DYNAMODB: {},
      self._FILE: {}
    }
  #-----------------------------------------------------------------------------
  def discriminate (self, path=None, bucket=None, key=None):
    """
    Discriminate between data sources
    """
    # A bucket and key are provided (S3)
    if path is None and bucket and key:
      source = self._S3
      path = f's3://{bucket}/{key}'
      client = self.clients\
        .get(self._S3)\
        .get(path) if path in self.clients.get(self._S3)\
          else S3Actor(bucket=bucket, region=self.s3Region)

    # An S3 URI is provided (S3)
    elif path[0:3] == "s3:":
      source = self._S3
      bucket, key = S3Actor.parseS3Url(path)
      client = self.clients\
        .get(self._S3)\
        .get(path) if path in self.clients.get(self._S3)\
          else S3Actor(bucket=bucket, region=self.s3Region)

    # A DynamoDb ARN is provided
    elif (path[0:4] == "arn:") and ("dynamodb" in path):
      source = self._DYNAMODB
      client = self.clients\
        .get(self._DYNAMODB)\
        .get(path) if path in self.clients.get(self._DYNAMODB)\
          else DynamoDbActor(tableArn=path)
 
    # Assume everything else is a local file
    else:
      source = self._FILE
      client = self.clients\
        .get(self._FILE)\
        .get(path) if path in self.clients.get(self._FILE)\
          else S3Actor(region=self.s3Region)

    # Set the client for future lookaside references
    self.clients[source][path] = client

    return source, client, path, bucket, key
  #-----------------------------------------------------------------------------
  def read (self, path=None, bucket=None, key=None):
    """ Read content """
    source, client, path, bucket, key = self.discriminate(path, bucket, key)

    emit("220130", "d", f'reading {source} from {path} ({bucket}/{key})')

    if source == self._S3:
      records = client.get(bucket=bucket, key=key).split("\n")
    elif source == self._DYNAMODB:
      records = client.scan()
    else:
      records = client.get(file=path).split("\n")

    return records
  #-----------------------------------------------------------------------------
  def csv (self, record=None):
    """
    Convert a list into a CSV string
    """
    # Generate CSV
    with io.StringIO() as file:
      writer = csv.writer(file, quoting=csv.QUOTE_ALL)
      writer.writerow(record)

      answer = file.getvalue()

    return answer
  #-----------------------------------------------------------------------------
  def write (self, path=None, bucket=None, key=None, records=None):
    """ Write content """
    source, client, path, bucket, key = self.discriminate(path, bucket, key)
    count = len(records)

    if source == self._S3:
      target = f'{path} ({bucket}/{key})'
    else:
      target = path if source != self._DYNAMODB else self.parseArn(path)

    emit("220140", "i", f'writing {count} records to {source} on {target}')

    if source == self._S3:
      response = client.put(outputObject=key, body="".join(
        [self.csv(record) for record in records]))
    elif source == self._DYNAMODB:
      response = []

      for record in records:
        response.append(client.putItem(record))
    else:
      response = []

      with open(path, "w") as file:
        for record in records:
          response.append(file.write(self.csv(record)))

    emit("220150", "d", f'response is\n{pprint.pformat(response)}')

    return count
  #-----------------------------------------------------------------------------
  def parseArn (self, arn=None, want=["path"]):
    """
    Parse an ARN and return requested components
    """
    if arn[0:4] != "arn:":
      raise ActorException(f'cannot parse [{arn}]')

    if arn.count(":") != 5:
      raise ActorException(f'incomplete ARN [{arn}]')

    components = dict(zip(
      ["eyecatcher", "partition", "service", "region", "account", "path"],
      arn.split(":")
    ))

    components["split"] = components.get("path").split("/")
    
    if isinstance(want, str):
      answer = components.get(want)
    elif isinstance(want, list):
      if (len(want) == 1):
        answer = components.get(want[0])
      else:
        answer = []
    
        for key in want:
          answer.append(components.get(key))
    else: 
      raise ActorException(f'cannot deal with {want.__class__.name}')

    return tuple(answer) if isinstance(answer, list) else answer
################################################################################
# 
################################################################################
class SsmActor (Actor):
    """
    Perform systems manager (SSM) actions.
    role      - role to assume for SSM operations
    region    - region in which SSM client will operate
    options   - set of options to process to resolve required parameters
    resolve   - a list of required parameters to be evaluated immediately
    configuration - a JSON configuration
    """
    #---------------------------------------------------------------------------
    def __init__ (self, role=None, region=None, options={}, resolve=[],
      configuration='{}'):
      """
      See the class definition for details.
      """
      super().__init__(service="ssm", region=region, role=role)

      self.parameters = {}

      self.resolve(
        options=options, 
        configuration=configuration,
        resolve=resolve
      )
    #---------------------------------------------------------------------------
    def resolve (self, options={}, configuration=None,
      resolve=[]):
      """
      options             The OptionsObject object containing invocation options
      configuration A JSON string containing named parameter configuration
      resolve             Parameter names for immediate resolutions

      The configuration for SSM parameters is submitted as a JSON object which
      contains the following keys:

      prefix      The value to be prepended to all SSM parameter names
      templates   A list of key-value pairs identifying the parameter names
                  to be constructed. The key is the parameter identifier, and
                  the value is a "%" template from which the name will be 
                  constructed using the prefix, the application name, and 
                  the environment name.
      """
      configuration = self._toObject(configuration)

      # Pitch a fit if required values aren't in the configuration
      if not ("prefix" in configuration) or not ("templates" in configuration):
        raise ActorException("configuration is missing required properties")

      # Track required arguments
      missing = []

      # Required arguments
      for name, template in configuration.get("templates").items():
        # If a list of names to resolve is provided, resolve only those names
        if resolve and not (name in resolve):
          emit("220300", "d", f'skipping {name} (not in the resolve list)')
          continue

        # Resolve the template
        values = template.count("%")
        prefix = configuration.get("prefix")

        if values == 1:
          resolved = template % prefix
        elif template.count("%") == 2:
          resolved = template % (prefix, options.environment)
        elif template.count("%") == 3:
          resolved = template % (prefix, options.environment, 
            options.application)
        else:
          raise ActorException(
            "%s template contains other than 1, 2, or 3 parameters" % name
          )

        emit("220310", "d", "resolved %s template %s to fqn '%s'" % 
          (name, template, resolved))

        value = self.getValue(resolved)

        self.parameters[name] = { 
          "name": resolved, 
          "value": value 
        }

        if not value:
          missing.append(resolved)
        else:
          emit("220320", "d", "parameter %s (%s) = %s" %
            (name, resolved, value))

        setattr(self, name, value)

      if missing:
        message = "required parameters have no value:\n"

        for name in missing:
          message += f"\t{name}\n"

        raise ActorException(message)
    #---------------------------------------------------------------------------
    def _toObject (self, string=None):
      """
      Turn a JSON string into an object
      """
      answer = None

      try:
        answer = json.loads(string)
      except (json.decoder.JSONDecodeError, TypeError) as thrown:
        raise ActorException("can't convert '%s' to JSON (%s): %s" 
          % (string, type(thrown), thrown))

      return answer
    #---------------------------------------------------------------------------
    def _resolve (self, nickname=None):
      """
      If this is a "named" parameter from the parameter configuration, the
      provided name is an alias that must be resolved to a fully qualified
      name.
      """
      if not(nickname in self.parameters):
        resolved = nickname
      else:
        resolved = self.parameters.get(nickname, {}).get("name", nickname)

        emit("220330", "d", f'setting {nickname} is really {resolved}')

      return resolved
    #---------------------------------------------------------------------------
    # Set an SSM parameter value
    def putValue (self=None, name=None, description=None, value=None, 
        type="String"):
        """
        Set the value of an SSM parameter.
        """
        # If this is a "named" parameter, the name provided is an alias
        # for the actual parameter.
        name = self._resolve(name)

        try:
            answer = self.client.put_parameter(
                Name=name,
                Description=description,
                Type=type,
                Value=value,
                Overwrite=True
           )

        except Exception as thrown:
            raise ActorException(
              f'Can\'t set SSM parameter {name} to \'{value}\': {thrown}'
            )

        return answer
    #---------------------------------------------------------------------------
    # Get SSM parameter values
    def getValue (self, name=None):
        """
        Retrieve the value of an SSM parameter.
        """
        answer = None
        
        try:
            name = self._resolve(name)
            response = self.client.get_parameters(Names=[name])
            answer = {}

            for candidate in response["Parameters"]:
                name = candidate["Name"]
                value = candidate["Value"]
                type = candidate["Type"]

                if type == "StringList":
                  answer = re.compile(r"\s*,\s*").split(value)
                else:
                  answer = value

            for name in response["InvalidParameters"]:
                emit("220340", "d", "parameter '%s' not found" % name)

        except Exception as thrown:
            raise ActorException("can't get SSM parameter %s: %s" % (name, thrown))

        return answer
################################################################################
# 
################################################################################
class DictionaryToObject:
    """
    Return an object that takes its attributes and values from the keys and
    values of a supplied Python dictionary.
    """
    def __init__ (self, descriptor=None, map=None,
      transform=lambda key: key[:1].lower() + key[1:]):
      """ See the class description for details """
      if isinstance(descriptor, dict):
        self.dictionary = descriptor
      elif isinstance(descriptor, str):
        try:
          self.dictionary = json.loads(descriptor)
        except json.decoder.JSONDecodeError as thrown:
          raise TypeError(f'DictionaryToObject bad JSON {descriptor}')
      else: 
        raise TypeError(f'DictionaryToObject bad type {descriptor} {type(descriptor).__name__}')

      self.transform = transform

      emit("220350", "d", f'processing {type(descriptor).__name__} {descriptor}')

      for key, value in self.dictionary.items():
          attribute = key if not callable(transform) else transform(key)

          # A property map was provided
          if isinstance(map, PropertyMap):
            emit("220360", "d", f'using PropertyMap for {key}')
            entry = map.getByKey(key)

            if isinstance(entry, PropertyEntry):
              value = entry.toInternal(value)
              emit("220370", "d", f'PropertyEntry map {key} to value {value}')

          if key != attribute:
            emit("220380", "d", f'{self.__class__.__name__} ' + 
              f'transformed {key} to {attribute}')

          setattr(self, attribute, value)
    #---------------------------------------------------------------------------
    def record (self):
      answer = {}

      for key, value in self.dictionary.items():
        attribute = key if not callable(self.transform) \
          else self.transform(key)

        value = getattr(self, attribute)
        answer[key] = value
      
      return answer
################################################################################
# 
################################################################################
class DynamoDbActor (Actor):
    """
    Concrete class that performs operations on DynamoDb tables.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, tableArn=None, creator=None, role=None):
        """ 
        See class definition for details 
        """
        emit("220540", "d", "DynamoDbActor table=%s" % tableArn)

        # Obtain details from table ARN: 
        match = self.parseArn(tableArn)

        # Initialize parent class
        super().__init__(
          partition=match.group("partitionId"),
          region=match.group("regionName"), 
          service="dynamodb", 
          role=role, 
          clientFactory=self.dynamoResource
        )

        # Properties specific to this actor
        self.creator = creator
        self.tableArn = tableArn
        self.tableName = match.group("tableName")
        self.table = self.client.Table(self.tableName)
        self.lowLevelClient = self.getClient(self.botoClient)

        emit("220550", "d", "DynamoDbActor role=%s, table=%s, region=%s" % \
            (self.role, tableArn, self.region))
    #---------------------------------------------------------------------------
    def parseArn (self, arn=None):
      """
      Parse a DynamoDb ARN into components
      """
      arn = arn if arn else self.tableArn

      # Obtain details from table ARN: 
      #   arn:<partition>:dynamodb:<region>:<accountId>:table/<tableName>
      _ROLE_PATTERN = \
        re.compile("^arn:(?P<partitionId>aws[-\w]*):dynamodb:" +
        "(?P<regionName>[-\w]+):(?P<accountId>\d{12}|\*):" +
        "table/(?P<tableName>.*)$")

      # Obtain details from the ARN
      try:
          match = _ROLE_PATTERN.match(arn)

      # Get better about catching RE parsing errors later
      except Exception as thrown:
          raise ActorException(f'cannot parse DynamoDb ARN {arn} ({thrown})')

      return match
    #---------------------------------------------------------------------------
    def tableExists (self, tableName=None):
      """
      Client factory to obtain a resource client for DynamoDB use
      """
      tableName = tableName if not(tableName is None) else self.tableName

      try:
        answer = self.lowLevelClient.describe_table(TableName=self.tableName)

      except Exception as thrown:
        emit ("0720", "d", f'describe_table failed on {tableName}: {thrown}')
        answer = False

      return answer
    #---------------------------------------------------------------------------
    def dynamoResource (self, **parameters):
      """
      Client factory to obtain a resource client for DynamoDB use
      """
      return boto3.resource(self.service, **parameters)
    #---------------------------------------------------------------------------
    def paginate (self, api=None, parameters={}):
      """
      Return multiple pages from a DynoamoDB call. 
      """
      token = None
      answer = []

      while True:
          if token:
              base = {"ExclusiveStartKey": token}
          else:
              base = {}

          parameters = {**base, **parameters}

          response = api(**parameters)
          token = response.get("LastEvaluatedKey", None)
          values = response.get("Items", [])

          answer += values

          if not token:
              break

      return answer
    #---------------------------------------------------------------------------
    def scan (self, parameters={}):
      """
      Scan a DynamoDB table--this version can process paged results.
      """
      answer = []

      try:
          answer = self.paginate(api=self.table.scan, parameters=parameters)
      except Exception as thrown:
          raise ActorException(f'scan table {self.tableName} failed {thrown}')
      else:        
          emit("220560", "d", "scan table %s results:\n%s" % 
              (self.tableName, pprint.pformat(answer)))

      return answer
    #---------------------------------------------------------------------------
    def query (self, parameters={}):
      """
      Perform a query against a DynamoDB table. The query covers a lot of ground
      so this method doesn't try to be smart--you specify the boto3 query 
      parameters necessary to return the results you want.
      """
      answer = []

      try:
          answer = self.paginate(api=self.table.query, parameters=parameters) 
      except Exception as thrown:
          raise ActorException(f'query table {self.tableName} failed {thrown}')
      else:        
          emit("220570", "d", f'query table {self.tableName} results from ' +
            f'{parameters} is\n{pprint.pformat(answer)}')

      return answer
    #---------------------------------------------------------------------------
    def putItem (self, item={}):
        """
        Put an item into a DynamoDb table
        """
        emit("220580", "d", f'DynamoDbActor putItem\n{pprint.pformat(item)}')
        response = self.table.put_item(Item=item)

        return response
    #---------------------------------------------------------------------------
    def updateItem (self, keys={}, set={}):
      """
      Carry out an update
      """
      updates = []
      expressionNames = {}
      expressionValues = {}
      #
      for key, value in set.items():
        updates.append(f'#{key} = :{key}')
        expressionNames["#"+key] = key
        expressionValues[":"+key] = value
      #
      updateExpression = "SET " + ", ".join(updates)
      #
      parameters = {
        "Key": keys,
        "UpdateExpression": updateExpression,
        "ExpressionAttributeNames": expressionNames,
        "ExpressionAttributeValues": expressionValues
      }
      #
      return parameters
################################################################################
# 
################################################################################
class OptionDescriptor:
  """
  Describes an argument for an OptionsObject
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, name=None, default=None, action=None):
    """ See class definition """
    self.name = name
    self.default = default
    self.action = action
  #-----------------------------------------------------------------------------
  def __str__ (self):
    """ String representation """
    answer = "<OptionDescriptor>\n"
    answer += f"\t<Name>{self.name}</Name>\n"
    answer += f"\t<Default>{self.default}</Default>\n"
    answer += f"\t<Action>{self.action}</Action>\n"
    answer += "</OptionDescriptor>\n"

    return answer
################################################################################
# 
################################################################################
class OptionsObject:
  """
  """
  _CONFIGURATION = re.sub(r'[\s\n]+', " ", """
    {
        "prefix": "/amtrak/cloud-solutions/dr",
        "templates": { 
          "instance": "%s/ec2/%s/%s",
          "securityGroup": "%s/ec2/%s/securitygroup-restricted",
          "subnet": "%s/ec2/%s/subnet",
          "vpc": "%s/vpc/%s",
          "itemStateTable": "%s/dynamodb/table/items",
          "sessionStateTable": "%s/dynamodb/table/sessions",
          "bucket": "%s/s3/bucket",
          "code": "%s/s3/code-folder",
          "archiveKey": "%s/s3/archive-key",
          "subnets": "%s/ec2/%s/subnets"
        }
      }
  """).strip()

  _PROPERTIES = [
    OptionDescriptor("liveRegion", "us-east-1", None),
    OptionDescriptor("recoveryRegion", "us-east-2", None),
    OptionDescriptor("debug", False, None),
    OptionDescriptor("environment", None, None),
    OptionDescriptor("application", None, None),
    OptionDescriptor("restoreInstances", None, 
      lambda things: sum(things, []) if isinstance(things, list) else []),
    OptionDescriptor("recoveryRole", None, None),
    OptionDescriptor("configuration", _CONFIGURATION, None),
    OptionDescriptor("ignoreMissing", False, None),
    OptionDescriptor("detail-type", None, None),
    OptionDescriptor("source", None, None),
    OptionDescriptor("detail", None, None),
    OptionDescriptor("playback", None, None),
    OptionDescriptor("forceComplete", False, None),
    OptionDescriptor("skipRecovery", False, None),
    OptionDescriptor("cleanup", False, None),
    OptionDescriptor("really", False, None),
    OptionDescriptor("complete", False, None),
    OptionDescriptor("status", False, None),
    OptionDescriptor("terminateDisconnected", False, None),
    OptionDescriptor("createLoadBalancer", False, None)
  ]
  #-----------------------------------------------------------------------------
  def __init__ (self, event=None, arguments=None):
    """
    Event is set if this is a Lambda invocation
    Arguments is set if this is a command line invocation
    """
    # Handle the case where we are initialized with our own class
    if isinstance(event, OptionsObject):
      for attribute in vars(event):
        value = getattr(event, attribute)
        setattr(self, attribute, value)

        emit("220990", "d", f'set option {attribute} to {value} from OptionsObject')

    # Handle other cases (dict or argparse object)
    else:
      for property in OptionsObject._PROPERTIES:
        name = property.name
        default = property.default
        action = property.action

        # Assign a value to the property as follows:
        # - Use the event if present
        # - Use the parseargs arguments if present
        # - Use the property default
        if event:
          candidate = event.get(name, default)
          valueSource = f"event[{name}]"
        elif arguments:
          candidate = getattr(arguments, name, default)
          valueSource = f"arguments.{name}"
        else:
          candidate = default
          valueSource = f"default={default}"

        # Now that we have a preliminary value
        # - Invoke the processing action if callable
        # - Set to candidate value or default 
        if callable(action):
          try:
            value = action(candidate)
            valuator = "action success"
          except TypeError as thrown:
            emit("221000", "w", "ignoring '%s'" % thrown)
            value = candidate
            valuator = "action error"
        else:
          if candidate:
            value = candidate
            valuator = "candidate"
          else:
            value = default
            valuator = "default"

        emit("221010", "d", "set argument %s to '%s' (candidate %s) using %s and %s" %
          (name, candidate, value, valueSource, valuator))

        setattr(self, name, value)
  #-----------------------------------------------------------------------------
  def record (self):
    """
    Return a serialized dict 
    """
    object = {}

    for property in OptionsObject._PROPERTIES:
      name = property.name
      value = getattr(self, name)

      object[name] = value

    return object
  #-----------------------------------------------------------------------------
  def __str__ (self):
    """
    String representation
    """
    return json.dumps(self.record())