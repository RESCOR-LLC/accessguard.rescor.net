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
class RandomId:
  """
  Generate a random ID
  """
  _SET_HEXADECIMAL = "01234567890abcdef"
  _TEMPLATE_INSTANCE_ID = 'i-_________________'
  _TEMPLATE_JOB_ID = '________-____-____-____-____________'
  #-----------------------------------------------------------------------------
  @staticmethod
  def jobId ():
    """
    Return a backup job ID
    """
    return RandomId.generate(RandomId._TEMPLATE_JOB_ID, 
      RandomId._SET_HEXADECIMAL, upper=True)
  #-----------------------------------------------------------------------------
  @staticmethod
  def instanceId ():
    """
    Return an EC2 instance ID 
    """
    return RandomId.generate(RandomId._TEMPLATE_INSTANCE_ID, 
      RandomId._SET_HEXADECIMAL, lower=True)
  #-----------------------------------------------------------------------------
  @staticmethod
  def generate (template=None, set=None, upper=False, lower=False):
    """
    This code generates the ID
    """
    answer = ""

    for place in template:
      answer += place if place != "_" else random.choice(set)

    if lower:
      answer = answer.lower()
    elif upper:
      answer = answer.upper()
    
    return answer
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
class SessionJobDetail:
  """
  Maps instance detail in the DynamoDb persistent state table. Instance detail
  includes the following attributes:

  - SourceId        -- the source EC2 instance ID
  - TargetId        -- the target EC2 instance ID
  - TargetState     -- the target EC2 instance state
  - RestoreJobId    -- the restore job ID
  - RestoreJobState -- the restore job state
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, record={}, sourceId=None, targetId=None, targetState=None, 
    restoreJobId=None, restoreJobState=None):
    """ See class definition for detail """
    # A record from DynamoDb was provided 
    if record:
      self.sourceId = record.get("SourceId")
      self.targetId = record.get("TargetId")
      self.targetState = record.get("TargetState")
      self.restoreJobId = record.get("RestoreJobId")
      self.restoreJobState = record.get("RestoreJobState")
    # Initialize from keyword parameters
    else:
      self.sourceId = sourceId
      self.targetId = targetId
      self.targetState = targetState
      self.restoreJobId = restoreJobId
      self.restoreJobState = restoreJobState
  #-----------------------------------------------------------------------------
  def complete (self):
    """ 
    Return True if the restore job has completed and the associated instance
    is running.
    """
    return (self.restoreJobState == "COMPLETED") \
      and (self.targetState == "running")
  #-----------------------------------------------------------------------------
  def record (self):
    """
    Return a JSON-serializable record for this instance detail
    """
    answer = {
      "SourceId": self.sourceId,
      "TargetId": self.targetId,
      "TargetState": self.targetState,
      "RestoreJobId" : self.restoreJobId,
      "RestoreJobState" : self.restoreJobState
    }

    return answer
  #-----------------------------------------------------------------------------
  def __str__ (self):
    """
    Display a string representation
    """
    return json.dumps(self.record())
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
class Ec2Actor (Actor):
  """
  Performs operations on EC2 instances
  """
  def __init__ (self, region=None, role=None):
    """ See class definition """
    super().__init__(service="ec2", region=region, role=role)
  #-----------------------------------------------------------------------------
  def tagInstances (self, instances=[], tags=[]):
    """
    Apply tags to a set of instances. 

    instances:list  -- a list of instance IDs to tag
    tags:list       -- a list of dicts with tag names and values
    """
    emit("220160", "d", f'tagInstances received {instances} {tags}')

    # Make the instance a list if a scalar instance name was provided
    instances = instances if isinstance(instances, list) else [ instances ]

    # Make th etags into a list in the same way
    tags = tags if isinstance(tags, list) else [ tags ]

    # Now process tags to remove any "aws:" tags
    tags = [ tag for tag in tags if tag.get("Key")[0:4] != "aws:" ]

    for tag in tags:
      emit("220170", "i", 
        f'setting tag {tag.get("Key")} to {tag.get("Value")}')

    # Call the API to apply the tags
    response = self.client.create_tags(
      Resources=instances,
      Tags=tags
    )

    return response
  #-----------------------------------------------------------------------------
  def terminateInstances (self, instances=[], ignoreMissing=True):
    """
    Terminate instances
    """
    instances = instances if isinstance(instances, list) else [ instances ]

    try:
      answer = self.client.terminate_instances(InstanceIds=instances)\
        .get("TerminatingInstances", [])

    except botocore.exceptions.ClientError as thrown:
      response = thrown.response.get("Error", {})
      code = response.get("Code")
      message = response.get("Message")

      if (code != "InvalidInstanceID.NotFound") or not ignoreMissing:
        raise thrown

      match = re.search(
        r'(The instance (?P<singular>ID) \'(?P<id>i-\w+)\')|' +
        r'(The instance (?P<plural>IDs) \'(?P<ids>.*)\')', message)

      if match:
        if match.group("singular"):
          suspects = [ match.group("id") ]
        else:
          suspects = match.group("ids").split(", ")

      for suspect in suspects:
        emit("220180", "w", f'instance {suspect} already terminated')
    
      answer = []

    return answer
  #-----------------------------------------------------------------------------
  def describeInstances (self, instances=[], filters=[]):
    """
    Describe instances
    """
    instances = instances if isinstance(instances, list) else [ instances ]

    raw = self.client.describe_instances(InstanceIds=instances, Filters=filters)
    reservations = raw.get("Reservations")
    answer = [] if not reservations else reservations[0].get("Instances")

    return answer
  #-----------------------------------------------------------------------------
  def describeImages (self, images=[], filters=[]):
    """
    Describe AMIs
    """
    images = images if isinstance(images, list) else [ images ]
    images = [ image if image[0:4] != "arn:" else image.split("/")[1]
      for image in images ]

    raw = self.client.describe_images(ImageIds=images, Filters=filters)
    images = raw.get("Images")

    return images
  #-----------------------------------------------------------------------------
  def imageTags (self, descriptor=None, prefix="dr-"):
    """
    Return the tags from an AMI descriptor returned by describeImages. The Name
    tag is modified using the specified prefix.
    """
    tags = descriptor.get("Tags", [])
    answer = []

    for tag in tags:
      key = tag.get("Key")

      if key == "Name":
        tagEntry = { "Key": key, "Value": prefix + tag.get("Value") }
      else:
        tagEntry = tag

      answer.append(tagEntry)

    return answer
################################################################################
# 
################################################################################
class LoadBalancingActor (Actor):
  """
  Performs operations on Application Load Balancer (ELBv2) instances
  """
  # Translate from ARN to unique ID
  _ID_FROM_ARN = lambda value: value.split(":")[5] 
  # Translate from whatever string to a usable name
  _NAME_FROM_STRING = lambda value: re.sub(r'\W', "-", value)
  # Return a tag pair for name
  _TAG_PAIR = lambda value: {"Key": "AdrApplicationEnvironment", "Value": value}
  # List of critical attributes
  _ATTRIBUTES = ["balancers", "listeners", "targetGroups", "registrations"]
  #-----------------------------------------------------------------------------
  @staticmethod
  def _LIMITED_NAME (value, maximum=32):
    """
    Enforce a name length limitation 
    """
    pieces = re.split(r'\W+', value)
    answer = ""
    #
    for piece in reversed(pieces):
      cumulative = len(answer) + len(piece) + 1
      suffix = "" if not answer else ("-" + answer)
      #
      if cumulative > maximum:
        overage = cumulative - maximum
        answer = piece[0:-overage] + suffix
      else:
        answer = piece + suffix
      #
    return answer
  #-----------------------------------------------------------------------------
  def __init__ (self, region=None, role=None, record=None):
    """ See class definition """
    super().__init__(service="elbv2", region=region, role=role)

    for key in LoadBalancingActor._ATTRIBUTES:
      if isinstance(record, dict) and (key in record):
        setattr(self, key, record.get(key))
        emit("220190", "i", f'initialize {key} to {record.get(key)}')
      else:
        setattr(self, key, {})
        emit("220200", "i", f'default set for {key}')
  #-----------------------------------------------------------------------------
  def addComponent (self, attribute=None, id=None, arn=None, details=None):
    """
    Add a load balancer component (balancer, listener, target group, registration)
    to the list of that component
    """
    current = getattr(self, attribute, {})

    emit("220210", "i", f'adding {id} (arn {arn}) to {attribute}')

    current[id] = details
    current[arn] = details

    setattr(self, attribute, current)

    return self
  #-----------------------------------------------------------------------------
  def getComponent (self, attribute=None, id=None, arn=None, throw=False):
    """
    Retrieve a load balancer component (balancer, listener, target group, 
    registration) from the list for that componet.

    ARN is preferred to ID if both are specified
    """
    key = arn if arn else id
    current = getattr(self, attribute, {})

    if not(key in current) and throw:
      raise NoStateRecord(f'nothing matching {key} in {attribute}')

    value = current.get(key)

    return value
  #-----------------------------------------------------------------------------
  def componentGenerator (self, attribute=None):
    """
    Loop through the contents of a component map and yield each key/value
    pair
    """
    current = getattr(self, attribute, {})

    for id, detail in current.items():
      yield id, detail
  #-----------------------------------------------------------------------------
  def record (self):
    """
    Return key attributes
    """
    answer = {}

    for key in LoadBalancingActor._ATTRIBUTES:
      answer[key] = getattr(self, key, {})

    return answer
  #-----------------------------------------------------------------------------
  def deleteBalancer (self, arn=None):
    """
    Delete a load balancer
    """
    if arn[0:4] == "arn:":
      id = LoadBalancingActor._ID_FROM_ARN(arn)
    else:
      id = arn
      arn = self.balancers.get(id).get("LoadBalancerArn")

    emit("220220", "i", f'deleting load balancer {id}')

    self.client.delete_load_balancer(LoadBalancerArn=arn)

    if id in self.balancers:
      del self.balancers[id]

      for listenerId, listener in self.listeners.items():
        if listener.get("LoadBalancerArn") == arn:
          del self.listeners[listenerId]
  #-----------------------------------------------------------------------------
  def deleteTargetGroup (self, arn=None):
    """
    Delete a target group
    """
    if arn[0:4] == "arn:":
      id = LoadBalancingActor._ID_FROM_ARN(arn)
    else:
      id = arn
      arn = self.targetGroups.get(id).get("TargetGroupArn")

    emit("220230", "i", f'deleting target group {id}')

    self.client.delete_target_group(TargetGroupArn=arn)

    if id in self.targetGroups:
      del self.targetGroups[id]
  #-----------------------------------------------------------------------------
  def createBalancer (self, name=None, subnets=None):
    """
    Create an application load balancer
    """
    actual = LoadBalancingActor._LIMITED_NAME(LoadBalancingActor._NAME_FROM_STRING(name))

    if (actual != name):
      emit("220240", "w", f'transmogrified {name} to {actual}')

    emit("220250", "i", f'creating ALB {actual} with subnets {subnets}')

    response = self.client.create_load_balancer(Name=actual, Type="application",
      Subnets=subnets, Tags=[LoadBalancingActor._TAG_PAIR(name)]).get("LoadBalancers")[0]

    # This annoyance is necessary because datetime.dateime objects appear here
    response["CreatedTime"] = str(response["CreatedTime"])

    arn = response.get("LoadBalancerArn")
    id = LoadBalancingActor._ID_FROM_ARN(arn)

    self.balancers[id] = response

    return id, arn
  #-----------------------------------------------------------------------------
  #-----------------------------------------------------------------------------
  def createTargetGroup (self, name=None, protocol=None, port=None, vpc=None,
    tags=[]):
    """
    Create target groups for ALB
    """
    actual = LoadBalancingActor._LIMITED_NAME(LoadBalancingActor._NAME_FROM_STRING(name) +
       "-" + protocol + "-" + str(port))

    emit("220260", "i", f'creating target group {actual}')

    response = self.client.create_target_group(Name=actual, Protocol=protocol,
      Port=port, VpcId=vpc, Tags=[LoadBalancingActor._TAG_PAIR(name)]).get("TargetGroups")[0]

    arn = response.get("TargetGroupArn")
    id = LoadBalancingActor._ID_FROM_ARN(arn)

    self.targetGroups[id] = response

    return id, arn
  #-----------------------------------------------------------------------------
  def createListener (self, name=None, balancer=None, protocol=None, port=None, 
    target=None, certificate=None):
    """
    Create listener for ALB and target group
    """
    emit("220270", "i", f'creating listener for {protocol} on {port}' + 
      f' forwarding to {target}')

    parameters = {
      "LoadBalancerArn": balancer,
      "Protocol": protocol,
      "Port": port,
      "DefaultActions": [{"Type": "forward", "TargetGroupArn": target}],
      "Tags": [LoadBalancingActor._TAG_PAIR(name)]
    }

    if protocol == "HTTPS":
      parameters["Certificates"] = [{"CertificateArn": certificate}]

    response = self.client.create_listener(**parameters).get("Listeners")[0]

    arn = response.get("ListenerArn")
    id = LoadBalancingActor._ID_FROM_ARN(arn)

    self.listeners[id] = response

    return id, arn
  #-----------------------------------------------------------------------------
  def registerTarget (self, instances=None, targetGroups=None):
    """
    Register targets with target groups
    """
    if not isinstance(instances, list):
      instances = [ instances ]

    # Convert to a format the API can use
    targets = [ { "Id" : instance } for instance in instances ]
    groups = []

    # If no target groups passed, we can use the internal map
    if not targetGroups:
      for groupId, group in self.targetGroups:
        emit("220280", "i", f'processing {groupId} details {group}')

        groups.append(group.get("TargetGroupArn"))
    
    # If a target groups list is passed, deal with that list
    else:
      for group in targetGroups:
        if group[0:4] != "arn:":
          raise RecoveryException(f'{group} is not an ARN')

        groups.append(group)

    # Now register with target groups
    for arn in groups:
      emit("220290", "i", f'registering {instances} with target group {arn}')

      self.client.register_targets(TargetGroupArn=arn,
        Targets=targets)
    
    return groups
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
class RestoreJobListing (DictionaryToObject):
  """
  Wrap the results of a list_restore_jobs dictionary item
  """
  def __init__ (self, descriptor=None):
    """ See class definition for details """
    super().__init__(descriptor=descriptor)
  #-----------------------------------------------------------------------------
  def state (self):
    """
    Return the state of the job listing
    """
    return self.status
  #-----------------------------------------------------------------------------
  def finished (self):
    """
    Return True if the job is finished--either completed, failed, or aborted
    """
    return self.status in ["COMPLETED", "FAILED", "ABORTED"]
  #-----------------------------------------------------------------------------
  def inList (self, jobs=[]):
    """
    Return true if this job is in a list of job IDs
    """
    return self.restoreJobId in jobs
################################################################################
#
################################################################################
class BackupActor (Actor):
  """
  Implement actions for AWS Backup
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, region=None, role=None, securityGroup=None, vpc=None, 
    subnet=None):
    """ See class definition for details """
    super().__init__(service="backup", region=region, role=role)

    self.securityGroup = securityGroup
    self.vpc = vpc
    self.subnet = subnet
    self.jobs = {
      "restore": {}
    }
    self.tags = {}
  #-----------------------------------------------------------------------------
  def getInstanceArn (self, instanceId=None, region="us-east-1"):
    """
    Return an ARN for an EC2 instance
    """
    answer = instanceId if instanceId[0:3] == "arn" else \
      f"arn:{self.partition}:ec2:{region}:{self.accountId}:instance/{instanceId}"

    return answer
  #-----------------------------------------------------------------------------
  def getInstanceId (self, arn=None):
    """
    Return an instance ID given an instance ARN
    """
    answer = arn if arn[0:2] == "i-" else arn.split("/")[1]

    return answer
  #-----------------------------------------------------------------------------
  def listRecoveryPoints (self, resourceArn=None):
    """
    List the recovery points for a resource in reverse order of completion (most
    recent recovery point will appear first)
    """
    resourceArn = resourceArn if resourceArn[0:3] == "arn" \
      else self.getInstanceArn(resourceArn)

    try:
      response = self.page(
        api=self.client.list_recovery_points_by_resource,
        fence="RecoveryPoints",
        additional={"ResourceArn" : resourceArn}
      )

      # Sort in reverse order by creation date
      final = sorted(
        response,
        key=lambda item: item["CreationDate"],
        reverse=True
      )

    # This is a stub of an exception handler -- it will be fleshed out
    except Exception as thrown:
      raise thrown

    return final
  #-----------------------------------------------------------------------------
  def recoveryPointMetadata (self, recoveryPoint=None):
    """
    Obtain the recovery metadata for a given recovery point
    """
    vault = recoveryPoint.get("BackupVaultName")
    arn = recoveryPoint.get("RecoveryPointArn")

    try:
      response = self.client.get_recovery_point_restore_metadata(
        BackupVaultName=vault,
        RecoveryPointArn=arn
      )

    # This is a stub of an exception handler -- it will be fleshed out
    except Exception as thrown:
      raise thrown

    return response.get("RestoreMetadata")
  #-----------------------------------------------------------------------------
  def getLastRecoveryPoint (self, resourceArnList=[], history=0, 
    ignoreMissng=False):
    """
    Initiate recovery jobs for a list of resources. The "history" parameter 
    specifies which recovery point is to be used, where "0" means the most
    recent recovery point, "1" means the next most recent recovery point, etc.
    """
    target = {}

    for resourceArn in resourceArnList:
      recoveryPoints = self.listRecoveryPoints(resourceArn)

      if len(recoveryPoints) == 0:
        if ignoreMissng:
          emit("220390", "w", f'ignoring missing recovery point for instance {resourceArn}')
          continue
        else:
          raise ActorException(f'no recovery points for instance {resourceArn}')

      targetPoint = recoveryPoints[history]
      metaData = self.recoveryPointMetadata(targetPoint)
      fullArn = self.getInstanceArn(resourceArn)

      target[fullArn] = {
        "instanceId": self.getInstanceId(fullArn),
        "resourceArn": fullArn,
        "recoveryPointList": recoveryPoints,
        "history": history,
        "targetPoint": targetPoint,
        "metaData" : metaData
      }

    return target
  #-----------------------------------------------------------------------------
  def performRecovery (self, target={}, role=None, skip=False, instanceClient=None):
    """
    Start restore jobs 
    """
    for arn, target in target.items():
      instance = arn.split(":")[5]
      metaData = self.massageMetadata(target.get("metaData"))

      # We aren't actually launching restore jobs, but we can fake it
      if skip:
        action = "simulated"
        severity = "w"
        #instance = RandomId.instanceId()
        job = RandomId.jobId()

      # Actually launch the restore job
      else:
        # The target point ARN is an AMI ARN when dealing with EC2
        imageArn = target.get("targetPoint").get("RecoveryPointArn")

        # Get the details for this image
        imageDetails = instanceClient.describeImages(imageArn)

        # Extract the tags for this image and store them in the tags property
        for imageDetail in imageDetails:
          tags = instanceClient.imageTags(imageDetail)

          self.tags[instance] = tags
          self.tags[arn] = tags

        # Start the restore job
        response = self.client.start_restore_job(
          RecoveryPointArn=imageArn,
          Metadata=metaData,
          IamRoleArn=role
        )

        action = "initiated"
        severity = "i"
        #instance = arn.split(":")[5]
        job = response.get("RestoreJobId")

      # Track the job
      self.jobs["restore"][arn] = job

      # Log the action taken
      emit("220400", severity, f'{instance} restore job {action} {job}')
      
    return self.jobs.get("restore"), self.tags
  #-----------------------------------------------------------------------------
  def listRestoreJobs (self, status=["PENDING", "RUNNING"]):
    """
    List all restore jobs
    """
    # Return data for all jobs 
    if not isinstance(status, list):
      emit("220410", "d", "listing jobs for all statuses")
      jobs = self.page(api=self.client.list_restore_jobs, fence="RestoreJobs")
    else:
      emit("220420", "d", f'listing jobs for statuses {status}')
      jobs = []

      for candidate in status:
        emit("220430", "d", f'listing jobs for status {candidate}')

        jobs += self.page(api=self.client.list_restore_jobs,
          fence="RestoreJobs", additional={"ByStatus": candidate})

    answer = {}

    for job in jobs:
      emit("220440", "d", f'objectifying {job}')
      jobObject = RestoreJobListing(job)
      answer[jobObject.restoreJobId] = jobObject

    return answer
  #-----------------------------------------------------------------------------
  def describeRestoreJob (self, resourceArn=None, jobId=None):
    """
    Get restore job details
    """

    if resourceArn:
      target = self.jobs.get("restore", {}).get(resourceArn)
    else:
      target = jobId
 
    response = self.client.describe_restore_job(
      RestoreJobId=target
    )

    return response
  #-----------------------------------------------------------------------------
  def massageMetadata (self, metaData=None):
    """
    The metadata from the recovery point cannot be used verbatim. This 
    method is built from trial and error based on what items must be 
    retained and what must be removed.
    """
    # The list of attributes to keep includes the attribute name and
    # an action--if the action is callable, it is used to process the
    # supplied value; else the value is simply copied.
    keep = {
      #"NetworkInterfaces" : self.massageInterfaces, 
      #"CpuOptions" : True, <== exclude nano, micro
      "EbsOptimized" : True,
      "InstanceInitiatedShutdownBehavior" : True,
      "InstanceType": True,
      "KeyName": True,
      "SecurityGroupIds": self.massageSecurityGroups,
      "aws:backup:request-id" : True,
      "VpcId" : self.massageVpc,
      "SubnetId" : self.massageSubnet
    }

    originalMetadata = {}

    for key, value in metaData.items():
      try:
        originalMetadata[key] = json.loads(value)
      except: 
        originalMetadata[key] = value

    emit("220450", "d", "original metadata %s" % 
      pprint.pformat(originalMetadata, indent=2))

    answer = {}

    for key, value in metaData.items():
      if key in keep:
        answer[key] = value if not callable(keep[key]) else keep[key](value)

    updatedMetadata = {}

    for key, value in answer.items():
      try:
        updatedMetadata[key] = json.loads(value)
      except:
        updatedMetadata[key] = value

    emit("220460", "d", "updated metadata %s" % 
      pprint.pformat(updatedMetadata, indent=2))

    return answer
  #-----------------------------------------------------------------------------
  def massageSecurityGroups (self, groups=None):
    """
    Replace the security groups with a target security group
    """
    candidate = getattr(self, "securityGroup", None)

    if candidate is None:
      replacement = None
      emit("220470", "d", "No overriding security groups found")
    elif isinstance(candidate, list):
      replacement = candidate
      emit("220480", "d", "Overriding security groups %s found" % candidate)
    elif isinstance(candidate, str):
      replacements = re.compile("/s*,/s*").split(candidate)
      emit("220490", "d", "Overriding security groups %s => %s found" %
        (candidate, replacements))
    else:
      emit("220500", "e", "don't know how to deal with security groups %s of type %s" %
        (candidate, type(candidate)))

    return json.dumps(replacement)
  #-----------------------------------------------------------------------------
  def massageSubnet (self, original=None):
    """
    Return the replacement subnet
    """
    emit("220510", "d", f'replacing subnet {original} with {self.subnet}')
    return self.subnet
  #-----------------------------------------------------------------------------
  def massageVpc (self, original=None):
    """
    Return the replacement VPC
    """
    emit("220520", "d", f'replacing VPC {original} with {self.vpc}')
    return self.vpc
  #-----------------------------------------------------------------------------
  def massageInterfaces (self, interfaces=None):
    """
    Massage the contents of the NetworkInterfaces list in the recovery point
    metadata
    """
    keep = [ "Description", "DeviceIndex", "DeleteOnTermination" , "InterfaceType" ]
    answer = []

    if isinstance(interfaces, str):
      interfaces = json.loads(interfaces)

    for interface in interfaces:
      massaged = {}

      for key, value in interface.items():
        if key in keep:
          massaged[key] = value
        else:
          emit("220530", "d", "discarding interface %s = '%s" % (key, value))

      answer.append(massaged)

    return json.dumps(answer)
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
class ValueHistory:
  """
  Implements a history of values for a given attribute or property name
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, names=[]):
    """ See class description for details """
    self.history = {}

    for name in names:
      self.history[name] = []
  #-----------------------------------------------------------------------------
  def push (self, name, value):
    """
    Add a value for a given name to its history
    """
    if not(name in self.history):
      self.history[name] = []

    self.history[name].append({ 
      "timestamp" : datetime.now().isoformat(), 
      "value": value })
  #-----------------------------------------------------------------------------
  def pop (self, name, leave=False):
    """
    Pop the most recent value from the history, optionally leaving the value
    in the history
    """
    if not(name in self.history):
      raise KeyError(f'{name} does not yet have any value history')
    elif len(self.history[name]) == 0:
      raise ValueError(f'{name} has an empty value history')
    elif leave:
      answer = self.history[name][-1]
    else:
      answer = self.history[name].pop()

    return answer
################################################################################
# 
################################################################################
class ValueMonitor:
  """
  Implements a value-checking descriptor that tracks the history of a value
  in an object and also allows us to display both gets and sets against that
  value
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, history=None, default=None, setter=None, getter=None):
    """
    Establish a default value to be used if none is supplied
    """
    emit("220590", "d", f'initialize with default {default}')

    self.history = history
    self.default = default
    self.setter = setter
    self.getter = getter
    self.owningClass = None
    self.publicName = None
    self.privateName = None
  #-----------------------------------------------------------------------------
  def __set_name__ (self, owner, name):
    """
    Automatically called at the time the owning class "owner" is created. The 
    object has been assigned to "name" in that class:
    """
    emit("220600", "d", f'recording {name} in class {owner.__name__}')

    self.owningClass = owner
    self.publicName = name
    self.privateName = "_" + name
  #-----------------------------------------------------------------------------
  def __set__ (self, object, value):
    """
    Called to set the attribute on an instance "object" of the owner class 
    to a new value "value."
    """
    emit("220610", "d", f'set {self.owningClass.__name__} ' +
      f'{self.publicName} = {value}')

    # Record history if necessary - to make this accessible to the owning 
    # class and intances requires this trickery of setting a class variable
    # in the owning class -- or does it?
    if isinstance(self.history, dict):
      candidate = getattr(object, self.privateName, self.default)
      previous = candidate if not callable(self.getter) else self.getter(candidate)

      if not (self.publicName in self.history):
        self.history[self.publicName] = []

      self.history[self.publicName].append(previous)

      emit("220620", "d", f'save old value {previous} history {self.history[self.publicName]}')

    # Transform the value if necessary
    answer = value if not callable(self.setter) else self.setter(value)

    # Set the new value
    setattr(object, self.privateName, answer)
  #-----------------------------------------------------------------------------
  def __get__ (self, object, owner=None):
    """
    Called to obtain the value of the attribute from instance "object" in 
    owning class "owner." 
    """
    # Obtain the value and manipulate it if necessary
    value = getattr(object, self.privateName, self.default)
    answer = value if not callable(self.getter) else self.getter(value)

    emit("220630", "d", f'get {self.owningClass.__name__} {self.publicName}: ' +
      f'{answer} (was {value})')

    return answer
################################################################################
# 
################################################################################
class ItemStateItem:
  """
  Represents an item state, and keeps track of the various attributes 
  associated with that item
  """
  # Item history
  _HISTORY = {}
  # Define descriptors
  set = ["date", "user", "ttl", "application", "environment", "tags", "type", 
    "id", "status", "changed"]

  date = ValueMonitor(_HISTORY)
  user = ValueMonitor(_HISTORY)
  ttl = ValueMonitor(_HISTORY)
  application = ValueMonitor(_HISTORY)
  environment = ValueMonitor(_HISTORY)
  tags = ValueMonitor(_HISTORY)
  type = ValueMonitor(_HISTORY)
  id = ValueMonitor(_HISTORY)
  status = ValueMonitor(_HISTORY)
  changed = ValueMonitor(_HISTORY)
  #-----------------------------------------------------------------------------
  def __init__ (self, **parameters):
    """ See class definition for details """
    for candidate, value in parameters.items():
      attribute = candidate[0].lower() + candidate[1:]

      if attribute != candidate:
        emit("220640", "i", f'transformed {candidate} to {attribute}')

      try:
        oldValue = getattr(self, attribute)
      except AttributeError as thrown:
        emit("220650", "w", f'ignoring unknown attribute {attribute}')
        continue

      emit("220660", "i", f'set {attribute} to {value} was {oldValue}')

      setattr(self, attribute, value)
  #-----------------------------------------------------------------------------
  def record (self, **parameters):
    """ Format an external record based on what's stored here """
    record = {}
    overrides = 0

    for attribute in self.set:
      key = attribute[0].upper() + attribute[1:]

      if not(key in parameters):
        value = getattr(self, attribute, None)
      else:
        value = parameters.get(key)
        overrides += 1

      record[key] = value

    emit("220670", "i", f'full record with {overrides} overrides is\n' +
      f'{pprint.pformat(record)}')

    return record
################################################################################
# 
################################################################################
class Persistence:
  """
  Contains common values, methods, and properties used by the Persistent*State
  classes
  """
  _TARGET_JOB = "job"
  _TARGET_INSTANCE = "instance"
  _TARGET_BALANCER = "balancer"
  _TARGETS = [ _TARGET_JOB, _TARGET_INSTANCE, _TARGET_BALANCER ]
  _COMPLETE = { 
    _TARGET_JOB: "COMPLETED", 
    _TARGET_INSTANCE: "running",
    _TARGET_BALANCER: "WTF" 
  }
################################################################################
# 
################################################################################
class PersistentItemState (DynamoDbActor, Persistence):
  """
  Track jobs and instances through update process. The following records may
  exist in this table:

  Instance Records:
    Date, User, TTL, Application, Environment, Type="instance", Id, 
      Status=[running, terminated, etc.]
  Job Records:
    Date, User, TTL, Application, Environment, Type="job", Id,
      Status=[CREATED, RUNNING, COMPLETED, FAILED]
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, tableArn=None, application=None, environment=None, 
    role=None, ttl=365.25/4):
    """ See class defintion """
    super().__init__(
      tableArn=tableArn,
      role=role
    )

    self.ttl = int(time.time() + 86400*365.25/4)
    self.application = application
    self.environment = environment
  #-----------------------------------------------------------------------------
  def setContext (self, item={}, options=None):
    """
    Set the context properties (application and environment) for the object. If
    the existing item has a context, use that; otherwise use that provided in 
    the options object.
    """
    # Values from the DynamoDb item
    oldApplication = item.get("Application")
    oldEnvironment = item.get("Environment")

    # Values from options object
    newApplication = getattr(options, "application")
    newEnvironment = getattr(options, "environment")

    # Use what we already have if non-None
    if oldApplication and oldEnvironment:
      source = "item"
      application = oldApplication
      environment = oldEnvironment
    
    # Choose values from options object otherwise, even if None
    else:
      source = "options"
      application = newApplication
      environment = newEnvironment

    # Set object properties
    self.application = application
    self.environment = environment

    emit("220680", "i", f'set item context using {source} ' +
      f'to {application}/{environment}')

    return self
  #-----------------------------------------------------------------------------
  def addItem (self, type=None, id=None, status=None, tags=[]):
    """
    Just another name for update
    """
    return self.updateItem(
      type=type, 
      id=id, 
      status=status, 
      operation="adding", 
      tags=tags
    )
  #-----------------------------------------------------------------------------
  def updateItem (self, type=None, id=None, status=None, operation="updating",
     tags=[]):
    """
    Create or update a state table record for a given type, id, and status
    """
    emit("220690", "d", f'PersistentItemState.update type={type} id={id} ' +
      f'status={status} operation={operation} tags={tags}')

    if not type in self._TARGETS:
      raise ActorException(f'unknown update target type {type}')

    answer = self.record(
      type=type, 
      id=id, 
      status=status, 
      tags=tags
    )

    emit("220700", "d", f'{operation} {type} {id} status {status}')

    self.putItem(answer)

    return answer
  #-----------------------------------------------------------------------------
  def isComplete (self, type=None, id=None):
    """
    Return true if the status is other than "forced" or "complete"
    """
    if not type in self._TARGETS:
      raise ActorException(f'unknown isComplete target type {type}')

    record = self.getItem(type, id)
    candidate = record.get("Status")

    emit("220710", "i", f'{type} {id} returns status {candidate} from {record}')

    current = candidate.upper() if not(candidate is None) else None
    goal = self._COMPLETE.get(type).upper()

    emit("220720", "d", f'checking completeness {type} {id}: {current} ' +
      f'must be {goal}')
    
    answer = current == goal

    return answer
  #-----------------------------------------------------------------------------
  def getItemList (self, type=None, context={}):
    """
    Retrieve a list of items in the database of a given type
    """
    displayType = type if type else "any"

    emit("220730", "d", f'listing {displayType} items')

    if type is None:
      answer = self.scan()
    else:
      answer = self.scan({"FilterExpression": Key("Type").eq(type)})\
        .get("Items", [])

    emit("220740", "d", f'found {len(answer)} {displayType} items')

    return answer
  #-----------------------------------------------------------------------------
  def getItem (self, type=None, id=None, create=False, context={}):
    """
    Retrieve information for this item. If the item doesn't exist, return
    a default record or generate an exception if create=False
    """
    emit("220750", "d", f'getting {type} {id} ({create})')

    items = self.query({"KeyConditionExpression": Key("Id").eq(id)})
    count = len(items)

    if count == 1:
      source = "query"
      answer = items[0]
    elif create and (count == 0):
      source = "create"
      answer = self.record(type, id)
    elif not create and (count == 0):
      raise NoStateRecord(f'no item for {type} {id}')
    elif items > 1:
      raise ActorException(f'too many items ({count}) for {type} {id}')

    # The application and environment from the query should be used if 
    # non-null, otherwise use the value from the context dict
    self.application = answer.get("Application") if answer.get("Application") \
      else context.get("Application")
    self.environment = answer.get("Environment") if answer.get("Environment") \
      else context.get("Environment")

    emit("220760", "d", f'item state from {source}:\n{pprint.pformat(answer)}')

    return answer
  #-----------------------------------------------------------------------------
  def record (self, type=None, id=None, status=None, tags=[]):
    """ 
    A master record defines a DR event and expires in a year
    """
    if not type in self._COMPLETE:
      raise ActorException("unknown record target type {type}")

    answer = {
      "Date": datetime.now().isoformat(),
      "User": self.principal,
      "TTL": self.ttl,
      "Application": self.application,
      "Environment": self.environment,
      "Tags": tags,
      "Type": type,
      "Id": id,
      "Status": status
    }

    emit("220770", "d", f'created record {pprint.pformat(answer)}')

    return answer
  #-----------------------------------------------------------------------------
  def deleteItem (self, type=None, id=None):
    """
    Delete the session record if one exists
    """
    if not self.getItem(type, id):
      emit("220780", "w", f'no item record for {type} {id}')
    else:
      try:
        self.table.delete_item(Key={ "Id": id })
        emit("220790", "w", f'item record deleted for {type} {id}')
      except Exception as thrown:
        emit("220800", "e", 'item record not deleted for ' + 
          f'{type} {id}: {thrown}')

    return self
################################################################################
# 
################################################################################
class PropertyMap:
  """
  Process and transform object properties
  """
  _BY_KEY = 1
  _BY_ATTRIBUTE = 2
  #-----------------------------------------------------------------------------
  def __init__ (self, entries=[]):
    """ See class definition """
    self.map = {}
    self.type = {}
    self.byKey = {}
    self.byAttribute = {}
    self.type = {}
    self.entries = []
    self.pointer = 0

    for entry in entries:
      # Can't deal if its not a property entry
      if not isinstance(entry, PropertyEntry):
        raise RecoveryException(f'{type(entry).__name__} is not a PropertyEntry')

      # Can't duplicate keys
      if entry.key in self.byKey:
        raise RecoveryException(f'entry key {entry.key} duplicated')

      # Can't duplicate entries
      if entry.attribute in self.byAttribute:
        raise RecoveryException(f'entry attribute {entry.attribute} duplicated')

      # Can't permit cross-map keys
      if (entry.attribute in self.byKey) or (entry.key in self.byAttribute):
        raise RecoveryException(f'cross map error [{entry.key}] [{entry.attribute}]')
        
      # Now perform the associations in the maps
      self.byKey[entry.key] = entry
      self.byAttribute[entry.attribute] = entry
      self.map[entry.key] = entry
      self.map[entry.attribute] = entry
      self.type[entry.key] = self._BY_KEY
      self.type[entry.attribute] = self._BY_ATTRIBUTE

      # Straight, entry-order entry list
      self.entries.append(entry)
  #-----------------------------------------------------------------------------
  def __iter__ (self):
    """ Implement iterable interface"""
    self.pointer = 0

    return self
  #-----------------------------------------------------------------------------
  def __next__ (self):
    """ Implement iterable interface """
    if self.pointer >= len(self.entries):
      raise StopIteration
    else:
      answer = self.entries[self.pointer]
      self.pointer += 1

    return answer
  #-----------------------------------------------------------------------------
  def getByKey (self, candidate=None): 
    """
    Return an entry from the byKey map
    """
    return self.byKey.get(candidate)
  #-----------------------------------------------------------------------------
  def getByAttribute (self, candidate=None):
    """
    Return an entry from the byAttribute map
    """
    return self.byAttribute.get(candidate)
  #-----------------------------------------------------------------------------
  def getByEither (self, candidate=None):
    """
    Return an entry based on either key or attribute name
    """
    return self.map.get(candidate)
  #-----------------------------------------------------------------------------
  def keyMap (self):
    """ Iterate over items in the byKey map """
    for key, value in self.byKey.items():
      yield key, value
  #-----------------------------------------------------------------------------
  def attributeMap (self):
    """ Iterate over items in the byAttribute map """
    for key, value in self.byAttribute.items():
      yield key, value
  #-----------------------------------------------------------------------------
  def eitherMap (self):
    """ Iterate over items by either key or attribute """
    for key, value in self.map.items():
      keyType = self.type.get(key)
      yield keyType, key, value
################################################################################
# 
################################################################################
class PropertyEntry:
  """
  Map a value in a DynamoDb item to an object attribute/property
  """
  #----------------------------------------------------------------------------
  def __init__ (self, key=None, attribute=None, default=None, toInternal=None, 
    toExternal=None):
    """ See class definition """
    self.key = key
    self.attribute = attribute
    self.default = default
    self._toInternal = toInternal
    self._toExternal = toExternal
  #-----------------------------------------------------------------------------
  def toInternal (self, external=None):
    """
    Transform a value from its serializable format to its internal format.

    source:any     -- External representation of value
    """
    internal = external if not callable(self._toInternal) else \
      self._toInternal(external)

    return internal
  #-----------------------------------------------------------------------------
  def toExternal (self, internal=None):
    """
    Transform a value from its internal format to its serializable format.

    internal:any    -- The value to be transformed to external representation
    """
    external = internal if not callable(self._toExternal) else \
      self._toExternal(internal)

    return external
################################################################################
# 
################################################################################
class TargetListEntry:
  """
  Map entity list values
  """
  def __init__ (self, type=None, map={}, id=None, state=None):
    """ See class definition """
    self.type = type

    if map:
      self.id = map.get("Id")
      self.state = map.get("State")
    else:
      self.id = id
      self.state = state
  #-----------------------------------------------------------------------------
  def getMap (self):
    """
    Return a map for updating the DynamoDb item
    """
    return { "id": self.id, "state": self.state }
  #-----------------------------------------------------------------------------
  def complete (self, state=None):
    """
    Return true if the item's state is complete
    """
    if state:
      self.state = state 

    answer = \
      ((self.type.lower() == "job") and (self.state.lower == "completed")) or \
      ((self.type.lower() == "instance") and (self.state.lower == "running"))

    return answer
################################################################################
# 
################################################################################
class PersistentSessionState (DynamoDbActor, Persistence):
  """
  An extension of the DynamoDbActor class that keeps state for the Amtrak DR
  function. 

  Parameters
  ----------
  tableArn:str            -- The DynamoDb table ARN  
  options:OptionsObject  -- The options used to invoke this program
  event:dict              -- The event object from a Lambda invocation 
  context:dict            -- The context object from a Lambda invocation
  role:str                -- An assumable role (can be None)
  new:bool                -- Should be a new state rather than an existing state
  ttl:float               -- The default TTL for DynamoDB records

  Attributes
  ----------
  date:str                -- ISO date stamp when this state was created
  ttl:int                 -- DynamoDB default TTL in epoch format
  application:str         -- The application name
  environment:str         -- The environment name (PROD or NONPROD)
  tag:str                 -- A combination of application and environment names
  options:OptionsObject  -- Program invocation options/arguments
  event:dict              -- Lambda event object
  context:dict            -- Lambda context object
  jobs:list               -- List of restore jobs and their state
  instances:list          -- List of instances and their state
  balancers:list          -- List of load balancers and their state
  """
  #-----------------------------------------------------------------------------
  _START = 1
  _RESUME = 2
  _BYPASS = 3
  #-----------------------------------------------------------------------------
  def __init__ (self, tableArn=None, operation=_START, application=None, 
    environment=None, force=False, role=None, ttl=3652.5, bypass=False):
    """ See class defintion """
    super().__init__(
      tableArn=tableArn,
      role=role
    )

    # Verify a complete key is provided
    self.checkSessionKey(application, environment)

    # Get any current record
    self.ttlDays = ttl
    self.raw = self.loadSession(useDefaults=False)

    # Verify the operation against current state and force flag
    # - Will raise exceptions if trying to continue without an 
    #   existing session state, or trying to start a new session 
    #   while state exists for this application/environment.
    self.checkSession(operation, force=force, bypass=bypass, record=self.raw)

    # Continuing an existing session, set from DynamoDb
    if operation != PersistentSessionState._START:
      self.setSession(**(self.raw if self.raw else self.defaults))

    # Explicitly start a new session with new values
    else:
      self.setSession(**self.defaults)
  #-----------------------------------------------------------------------------
  @property
  def defaults (self):
    """
    Return a dict with default object initialization values
    """
    answer = {
        "Date": datetime.now().isoformat(),
        "TTL": int(time.time() + 86400*self.ttlDays),
        "User": self.principal,
        "Id": str(uuid.uuid4()),
        "Type": "master",
        "Status": "open",
        "Event": {},
        "Context": {},
        "Options": OptionsObject({}),
        "Jobs": [],
        "Instances": [],
        "Balancers": []
    }

    return answer
  #-----------------------------------------------------------------------------
  def checkSessionKey (self, application=None, environment=None):
    """
    Both an application name and environment name, which comprise the partition 
    and sort key, must be provided and must be strings 
    """
    missing = []

    if not isinstance(application, str):
      missing.append("application")

    if not isinstance(environment, str):
      missing.append("environment")

    if missing:
      raise ActorException(f'missing required parameter {", ".join(missing)}')

    self.application = application
    self.environment = environment
    self.tag = f'{application}/{environment}'

    emit("220810", "d", f'valid key {self.tag} supplied')

    return self
  #-----------------------------------------------------------------------------
  def loadSession (self, useDefaults=True):
    """
    Retrieve session record for this tag. The session table is key such that 
    there can never be more than one state for a given tag (application
    and environment pair).
    """
    try:
      answer = self.query(self.queryKey)[0]
    except IndexError as thrown:
      answer = self.defaults if useDefaults else {}
      emit("220820", "d", f'no session for {self.tag} use defaults {useDefaults}')
    except Exception as thrown:
      answer = {}
      emit("220830", "w", f'no session for {self.tag}: {thrown}')

    return answer
  #-----------------------------------------------------------------------------
  def checkSession (self, operation=_START, force=False, bypass=False, record={}):
    """
    Raise exceptions if this is a start operation with an existing state but no
    "force" option, or a resume operation with no existing state. If bypass option
    is specific, this is a cleanup and missing state should be ignored.
    """
    active = record and not(record.get("Status") in ["forced", "complete"])

    # Handle case of resume operation with no state
    if (operation != PersistentSessionState._START) and not bypass and not active:
      raise ActorException(f'resume operation on non-existent state {self.tag}')

    # Handle case of start operation with existing state and no "force" option
    if (operation == PersistentSessionState._START) and active and not force:
      raise ActorException(f'start operation on existing state {self.tag}')

    # Warning if start operation with existing state but with "force" option
    if (operation == PersistentSessionState._START) and active and force:
      emit("220840", "w", f'superseding existing state for {self.tag}')

    return self
  #-----------------------------------------------------------------------------
  @property
  def updateKey (self):
    """ Return the DynamoDb update key structure """
    answer = {
      "Application": self.application ,
      "Environment": self.environment
    }

    return answer
  #-----------------------------------------------------------------------------
  @property
  def queryKey (self):
    """ Return the DynamoDb query key structure """
    answer = {
      "KeyConditionExpression":
        Key("Application").eq(self.application) &
        Key("Environment").eq(self.environment)
    }

    return answer
  #-----------------------------------------------------------------------------
  @property
  def transformMap (self):
    """ 
    Return the map to transform between internal and external representations
    """
    answer = PropertyMap([
      PropertyEntry("Date", "date"),
      PropertyEntry("User", "user"),
      PropertyEntry("TTL", "ttl"),
      PropertyEntry("Application", "application"),
      PropertyEntry("Environment", "environment"),
      PropertyEntry("Type", "type", "MASTER"),
      PropertyEntry("Id", "id"),
      PropertyEntry("Status", "status", default="open"),
      PropertyEntry("Event", "event", default={}),
      PropertyEntry("Context", "context", default={}),
      PropertyEntry("Options", "options", 
        toInternal=lambda value: OptionsObject(value),
        toExternal=lambda value: value.record()),
      PropertyEntry("Jobs", "jobs"),
      PropertyEntry("Balancers", "balancers"),
      PropertyEntry("Instances", "instances")
    ])

    return answer
  #-----------------------------------------------------------------------------
  @property
  def targetMap (self):
    """
    Return the map used to return target lists based on target types
    """
    answer = {
      "job": lambda : self.jobs,
      "jobs": lambda : self.jobs,
      "instance": lambda : self.instances,
      "instances": lambda : self.instances,
      "balancer": lambda : self.balancers,
      "balancers": lambda: self.balancers
    }

    return answer
  #-----------------------------------------------------------------------------
  def setSession (self, **parameters):
    """
    Set internal session state values from keyword parameters.
    """
    # Update object properties based on parameters passed 
    # "thing" can be either a dict key or attribute name
    for key, entry in self.transformMap.keyMap():
      if not(key in parameters):
        continue

      value = parameters.get(key)
      transformed = entry.toInternal(value) 

      setattr(self, entry.attribute, transformed)

      emit("220850", "d", f'set {key} ({entry.attribute}) ' +
        f'to {value} type {type(value).__name__} ({transformed})')

    return self
  #-----------------------------------------------------------------------------
  def saveSession (self):
    """
    Save the session state to DynamoDb
    """
    # Get external representation of state
    record = self.record()

    emit("220860", "i", f'session record is\n{pprint.pformat(record)}')

    # Update DynamoDb
    response = self.putItem(record)

    emit("220870", "i", f'saved session record for {self.tag}')
    emit("220880", "d", f'item content\n{pprint.pformat(record)}')
    emit("220890", "d", f'response from put_item\n{pprint.pformat(response)}')

    return self
  #-----------------------------------------------------------------------------
  def record (self): 
    """
    Convert the internal values from this object into DynamoDb (external)
    representations that can be serialized, written to DynamoDb items, etc.

    - Method "record" is an alias for "external"
    """
    # Initialze the destination
    external = {}

    # Massage properties to external representation
    for attribute, entry in self.transformMap.attributeMap():
      # Get the internal value from the object attribute
      oldValue = getattr(self, attribute)
      newValue = entry.toExternal(oldValue) 

      # Set the massaged value
      external[entry.key] = newValue

      emit("220900", "d", \
        f'i2x {attribute}=[{oldValue}] to {entry.key}=[{newValue}]')
       
    return external
  #-----------------------------------------------------------------------------
  def getTargetList (self, type=None):
    """
    Return the appropriate target list (jobs, instances, or balancers) as 
    specified by the "type." These targets are retained in the session record as 
    well as in item records, which may be unnecessary complexity but works for 
    now.
    """
    # Make the key to the targetMap case insensitive
    type = type.lower()

    # An unknown type was passed
    if not(type in self.targetMap):
      raise ActorException(f'unknown target type {type}')

    # The list of targets should be transformed by a callable function or lambda
    elif callable(self.targetMap[type]):
      branch = f'callable action for type {type}'
      answer = self.targetMap[type]()

    # The list of targets is, weirdly, a fixed value
    else:
      branch = f'value \'{self.targetMap[type]}\' for type {type}'
      answer = self.targetMap[type]

    # However it is obtained the target list must be, well, a list
    if not isinstance(answer, list):
      raise ActorException(f'invalid target class {type(answer).__name__}')
    else:
      valid = "list type"

    emit("220910", "d", f'getTargetList returns {valid} with {branch}: {answer}')

    return answer
  #-----------------------------------------------------------------------------
  def setBalancers (self, content=None):
    """
    The balancer property will receive the AlbActor "record" object so that we
    can reload the balancer details later for instance population or cleanup.
    """
    emit("220920", "i", f"set balancers to\n {pprint.pformat(content)}")

    self.balancers = content

    return self
  #-----------------------------------------------------------------------------
  def setTargetState (self, type=None, id=None, state=None):
    """
    Marks a target item (job, instance, balancer) with a given state in the 
    session state record but does _not_ update the database--you need to perform
    a separate save() operation to update the DynamoDb table.
    """
    # Changing this will automatically update the desired target list
    targets = self.getTargetList(type)

    # Update the target if it already exists
    try:
      target = next(target for target in targets if target.get("id") == id)
      oldState = target.get("state")
      target["state"] = state

      emit("220930", "d", f'updated {type} {id} to {state} from {oldState}')

    # Otherwise append a new target
    except StopIteration:
      targets.append({"type": type, "id": id, "state": state})

      emit("220940", "d", f'appending target {type} {id} state {state}')

    emit("220950", "d", f'now we have\n{pprint.pformat(targets)}')

    return self
  #-----------------------------------------------------------------------------
  def deleteSession (self):
    """
    Delete the session record if one exists
    """
    answer = False

    if not self.loadSession(useDefaults=False):
      emit("220960", "w", f'no session record for {self.tag}')
    else:
      try:
        self.table.delete_item(Key=self.updateKey)
        answer = True
        emit("220970", "w", f'session record deleted for {self.tag}')
      except Exception as thrown:
        emit("220980", "e", f'session record not deleted for {self.tag}: {thrown}')

    return answer
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
################################################################################
# 
################################################################################
class EventBridgeState:
  """
  An abstract class that represents event bridge event states
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, source=None, detail={}, keys={}, className=None):
    """ See class definition """
    emit("221020", "i", 
      f'source={source} detail={detail} keys={keys} className={className}')

    self.className = className
    self.source = source
    self.properties = {}
    self.status = detail.get("state") if "state" in detail \
      else detail.get("status")

    emit("221030", "i", f'setting {source} event status {self.status}')

    descriptors = keys.get(self.status, {})

    emit("221040", "d", f'found descriptors {descriptors} in {detail}')

    if not descriptors:
      raise IgnoredEvent(
        "Don't know how to handle", 
        eventSource=self.source, 
        eventName=self.status
      )

    for key, action in descriptors.items():
      emit("221050", "d", f'processing {key} {action} of {detail}')
      attribute = key

      if callable(action):
        value = action(detail.get(key))
      elif isinstance(action, str):
        value = detail.get(key)
        attribute = action
      else:
        value = detail.get(key)  

      setattr(self, attribute, value)

      if not (value is None):
        self.properties[attribute] = action
        emit("221060", "d", f'property {attribute} = \'{value}\'')
      else:
        emit("221070", "w", f'no value for property {attribute}')
  #-----------------------------------------------------------------------------
  def __str__ (self):
    """
    String representation
    """
    answer = f'<{self.className} state=\'{self.status}\'>\n'

    for key, _ in self.properties.items():
      answer += f'\t<{key}>{getattr(self, key)}</{key}>\n'

    answer += f'</{self.className}>'

    return answer
################################################################################
# 
################################################################################
class RestoreJobState (EventBridgeState):
  """
  An object to represent the restore job state
  """
  _KEYS = {
    "CREATED": {
      "restoreJobId": None,
      "creationDate": None, 
    },
    "COMPLETED": {
      "restoreJobId": None,
      "backupSizeInBytes": lambda value : int(value),
      "creationDate": None,
      "iamRoleArn": None,
      "resourceType": None,
      "createdResourceArn": None,
      "completionDate": None,
      "percentDone": lambda value: Decimal(str(value))
    },
    "RUNNING": {
      "backupSizeInBytes": lambda value : int(value),
      "creationDate": None,
      "iamRoleArn": None,
      "resourceType": None,
      "restoreJobId": None,
      "percentDone": lambda value: Decimal(str(value))
    }
  }
  #-----------------------------------------------------------------------------
  def __init__ (self, detail={}):
    """ See class definition """
    super().__init__(
      source="aws.backup", 
      detail=detail, 
      keys=RestoreJobState._KEYS,
      className=__class__.__name__ 
    )
################################################################################
# 
################################################################################
class InstanceState(EventBridgeState):
  """
  An object to represent the restore job state
  """
  _KEYS = {
    "shutting-down": {
      "instance-id": "instanceId"
    },
    "terminated": {
      "instance-id": "instanceId"
    },
    "pending" : {
      "instance-id": "instanceId"
    },
    "running" : {
      "instance-id": "instanceId"
    }
  }
  #-----------------------------------------------------------------------------
  def __init__ (self, detail={}):
    """ See class definition """
    super().__init__(
      source="aws.ec2",
      detail=detail,
      keys=InstanceState._KEYS,
      className=__class__.__name__
    )
################################################################################
# 
################################################################################
class Waiter:
  """
  Perform an operation with polling. An exponential backoff funciton is used 
  after each operation that returns "False," waiting for a number of sections
  before attempting the operation again
  """
  _BASE = 2.0       # Base for exponent
  _MAXIMUM = 60.0   # Maximum number of seconds to wait
  _CYCLES = 10      # Maximum number of waiting cycles
  #-----------------------------------------------------------------------------
  def __init__ (self, name=None, code=None, base=_BASE, maximum=_MAXIMUM):
    """ See class definition for details """
    self.name = name
    self.code = code
    self.base = base
    self.maximum = maximum
  #-----------------------------------------------------------------------------
  def wait (self, items=None, **parameters):
    """
    Perform the operation and wait on the results. The called operation code
    takes as input a key and value from the supplied list of items, and returns
    True if the operation was successful or False otherwise, and any details in 
    dict format:

    def example (key, value, **parameters):
      details = { "key": key "value": value, "parameters": parameters }
      success = doSomething(key, value)

      return success, details
    """
    cycle = 0 

    while True:   
      complete = True

      for key, value in items.items():
        success, details = self.code(key, value, **parameters)

        if not success:
          complete = False
          break

      if complete:
        emit("221080", "w", f'all operations complete for {self.name}')
        break

      time.sleep(min(Waiter._MAXIMUM, Waiter._BASE**cycle))
      cycle += 1

    return success, details
################################################################################
# 
################################################################################
class IgnoredEvent(Exception):
  """
  Exception to deal with a case where an event is ignored. Has a specific
  parameter "eventName" which contains the name of the operation that is 
  ignored.
  """
  def __init__ (self, *arguments, eventSource=None, eventName=None):
    """ See class definition """
    super().__init__(*arguments)

    self.eventName = eventName
    self.eventSource = eventSource
################################################################################
# 
################################################################################
class RecoveryException(Exception):
  """
  """
  pass
################################################################################
#
################################################################################
class NoStateRecord (Exception):
  """
  """
  pass
################################################################################
#
################################################################################
class SqsEventAttributes (DictionaryToObject):
  pass
################################################################################
#
################################################################################
class SqsEventBody (DictionaryToObject):
  def __init__ (self, descriptor=None): 
    super().__init__(descriptor)

    try:
      self.detail = SqsEventDetail(self.event.get("detail"))
    except AttributeError as thrown:
      raise IgnoredEvent(f'event does not contain required attributes\n' +
        f'{pprint.pformat(descriptor)}')
################################################################################
#
################################################################################
class SqsEventDetail (DictionaryToObject):
  pass
################################################################################
#
################################################################################
class SqsEvent:
  """
  """
  #-----------------------------------------------------------------------------
  _MAP = PropertyMap([
    PropertyEntry(key="attributes", attribute="attributes", default=None, 
      toInternal=lambda value: SqsEventAttributes(value), 
      toExternal=lambda value: value.record()),
    PropertyEntry(key="awsRegion", attribute="awsRegion", default=None),
    PropertyEntry(key="body", attribute="body", 
      toInternal=lambda value: SqsEventBody(value),
      toExternal=lambda value: value.record()),
    PropertyEntry(key="eventSource", attribute="eventSource", default=None),
    PropertyEntry(key="eventSourceArn", attribute="eventSourceArn", default=None),
    PropertyEntry(key="md5OfBody", attribute="md5OfBody", default=None),
    PropertyEntry(key="messageAttributes", attribute="messageAtributes", default=None),
    PropertyEntry(key="messageId", attribute="messageId", default=None),
    PropertyEntry(key="receiptHandle", attribute="receiptHandle", default=None)
  ])
  #-----------------------------------------------------------------------------
  def __init__ (self, event=None):
    for map in self._MAP:
      value = map.toInternal(event.get(map.key))

      setattr(self, map.attribute, value)
  #-----------------------------------------------------------------------------
  def record (self):
    answer = {}

    for map in self._MAP:
      value = map.toExternal(getattr(self, map.attribute))

      answer[map.key] = value

    return answer
