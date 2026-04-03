#! /usr/local/bin/python3
################################################################################
### See README.md
###############################################################################
import datetime
import hashlib
import json
import logging
import pprint
import re
import time
from json.encoder import JSONEncoder

import botocore
import commonClasses as cc

# Ephemeral credentials supported
_EPHEMERAL_CREDENTIALS_SUPPORTED = False

# Lambdas to obtain elements of a botocore ClientError
error = lambda thrown : thrown.get("Error", {}).get("Code", None)
message = lambda thrown : thrown.get("Error", {}).get("Message", None)

# Retrieve the logging instance. DEBUG level messages generate a huge volume
# of messages from AWS APIs, so the strategy here is to use INFO level messages
# and write debugging messages if the --debug flag is set.
_DEBUGGING = False
logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger()
_LOGGER.setLevel(logging.INFO)
################################################################################
# 
################################################################################
# Map IAM entities to objects
class IamUser (cc.DictionaryToObject): pass
class IamRole (cc.DictionaryToObject): pass
class IamGroup (cc.DictionaryToObject): pass
################################################################################
# 
################################################################################
class IamEntities:
    """
    An abstract class that represents supported IAM entities (currently user,
    group, and role)
    """
    #---------------------------------------------------------------------------
    def __init__ (self, entityClass=None, description=None, apis = {}, 
        preProcessor=None):
        """
        See the class definition for details.
        """
        self.name = description.lower()
        self.key = description.title()
        self.selector = self.key[0:-1] + "Name"
        self.property = self.key[0].lower() + self.key[1:-1] + "Name"
        self.entityClass = entityClass
        self.preProcessor = preProcessor
        self.api = {}
        self.entities = []
        self.count = 0

        for apiName, api in apis.items():
            self.api[apiName] = api
    #---------------------------------------------------------------------------
    def namedApi (self, name=None):
        """
        Return the callable API reference for a given operation. The operations
        supported vary based on the entity type, and are defined in the entity-
        specific subclasses.
        """
        return self.api.get(name)
    #---------------------------------------------------------------------------
    def policies (self, entity=None): 
        """
        Obtain all the inline policies associated with an entity return them as
        a JSON string.
        """
        listPolicies = self.namedApi("listPolicies")
        getPolicy = self.namedApi("getPolicy")
        answer = {}
        parameters = { self.selector : entity }

        if callable(listPolicies) and callable(getPolicy):
            for policyName in listPolicies(**parameters)["PolicyNames"]:
                parameters["PolicyName"] = policyName

                answer[policyName] = getPolicy(**parameters)["PolicyDocument"]

        return json.dumps(answer,indent=2)
    #---------------------------------------------------------------------------
    def managed (self, entity=None):
        """
        Obtain a list of all managed policies associated with an entity and 
        return them as a Python list.
        """
        listManaged = self.namedApi("listManaged")
        answer = []
        parameters = { self.selector : entity }

        if callable(listManaged):
            for policyDescriptor in listManaged(**parameters)["AttachedPolicies"]:
                answer.append(policyDescriptor.get("PolicyName"))

        return answer
    #---------------------------------------------------------------------------
    def members (self, entity=None):
        """
        Return the members of an entity (relevant only to groups)
        """
        return []
    #---------------------------------------------------------------------------
    def download (self):
        """
        Use the entity's list API to build a list of all entities of the 
        needful type.
        """
        api = self.namedApi("list")
        entities = []
        count = 0

        # Catch errors
        try:
            token = None

            # Loop to list all entities
            while True:
                # Call the API for the first or subsequent pages
                answer = api(MaxItems=100) if not token \
                    else api(MaxItems=100, Marker=token)

                token = answer.get("Marker", None)
                candidates = answer.get(self.key, [])
                count += len(candidates)

                # Process all entities retrieved this iteration
                for candidate in candidates:
                    # Invoke the preprocessor 
                    if callable(self.preProcessor):
                        candidate = self.preProcessor(candidate)

                    # Create an object of the appropriate type from the API 
                    # results
                    entity = self.entityClass(candidate)

                    # Store inline policies
                    policies = self.policies(getattr(entity, self.property))
                    setattr(entity, "policies", json.loads(policies))
                    entity.dictionary["policies"] = json.loads(policies)

                    # Store managed policies
                    managed = self.managed(getattr(entity, self.property))
                    setattr(entity, "managed", managed)
                    entity.dictionary["managed"] = managed

                    # Store members
                    members = self.members(getattr(entity, self.property))
                    setattr(entity, "members", members)
                    entity.dictionary["members"] = members

                    entities.append(entity)

                if not token:
                    break

        # Handle any failure
        except Exception as thrown:
            response = getattr(thrown, "response", {})
            message = str(thrown) if not response \
                else response["Error"]["Message"]

            raise Exception("(e) Cannot retrieve %s: %s" \
                % (self.name, message)).with_traceback(thrown.__traceback__)

        self.entities = entities
        self.count = count

        return entities
################################################################################
# 
################################################################################
class IamUsers (IamEntities):
    """
    Concrete class for IAM users.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, client=None):
        """ See the class definition for details. """
        apis = {
            "list" : client.list_users ,
            "listPolicies" : client.list_user_policies,
            "getPolicy" : client.get_user_policy ,
            "listManaged" : client.list_attached_user_policies
        }

        super().__init__(entityClass=IamUser, description="users", apis=apis)
################################################################################
# 
################################################################################
class IamGroups (IamEntities):
    """
    Concrete class for IAM groups.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, client = None):
        """ See the class definition for details. """
        apis = {
            "list" : client.list_groups ,
            "listPolicies" : client.list_group_policies,
            "getPolicy" : client.get_group_policy ,
            "listMembers" : client.get_group ,
            "listManaged" : client.list_attached_group_policies
        }

        super().__init__(entityClass=IamGroup, description="groups", apis=apis)
    #---------------------------------------------------------------------------
    def members (self, entity=None):
        """
        Implements the IamEntities.members method in the only context that
        matters (IAM groups)
        """
        listMembers = self.namedApi("listMembers")
        answer = []

        if callable(listMembers):
            for userDescriptor in listMembers(GroupName=entity)["Users"]:
                answer.append(userDescriptor["UserName"])

        return answer
################################################################################
# 
################################################################################
class IamRoles (IamEntities):
    """
    Concrete class for IAM roles.
    """
    def __init__ (self, client = None):
        """ See the class definition for details. """
        apis = {
            "list" : client.list_roles ,
            "listPolicies" : client.list_role_policies,
            "getPolicy" : client.get_role_policy ,
            "listManaged" : client.list_attached_role_policies
        }

        super().__init__(entityClass=IamRole, description="roles", apis=apis)
################################################################################
# 
################################################################################
class SimilarEntities:
    """
    Class to represent entities that are similar on some basis, which should
    help to simplify the role engineering process. Similar entities that can be
    detected are:

    1. The same managed policies
    2. The same member list (only groups)
    3. The same inline policy content (ignoring policy names)
    """
    #---------------------------------------------------------------------------
    def __init__ (self):
        """ See the class definition for details. """
        self.byManaged = {}
        self.byMembers = {}
        self.byInlinePolicy = {}
    #---------------------------------------------------------------------------
    def add (self, row=None):
        """
        Adds an entity to the similar entity lists
        """
        managedKey, membersKey, policyKey = self.keys(row)

        if managedKey:
            self.addToList(self.byManaged, managedKey, row)

        if membersKey:
            self.addToList(self.byMembers, membersKey, row)

        if policyKey:
            self.addToList(self.byInlinePolicy, policyKey, row)

        return self
    #---------------------------------------------------------------------------
    def addToList (self, target=None, key=None, row=None):
        """
        Add a row to a similarity list based on a key. If the key does not 
        exist, create a similarity list. Then append the row to the list.
        """
        if not (key in target): 
            target[key] = []

        target[key].append(row)

        return self
    #---------------------------------------------------------------------------
    def orderDescriptions (self, rows=None):
        """
        Extract the decriptions for a list of IamEntityRow object which has been
        sorted by the "name" attribute, then the "account" and "entityType" attribute.
        """

        return [row.arn for row in sorted(rows, 
            key=lambda row : (row.name, row.account, row.entityType))]
    #---------------------------------------------------------------------------
    def extractBySimilarity (self, items=None, attribute=None, similarity=None,
        format=dict):
        """
        Iterate over a collection of items and return a set of rows for the 
        Similar Entities sheet.
        """
        answer = []

        for key, rows in items:
          cc.emit("242010", "d", f'processing {similarity} similarity {key}')

          first = rows[0]

          if len(rows) <= 1:
            continue

          answer.append({
              "similarity": similarity,
              "by": getattr(first, attribute, []),
              "entities": self.orderDescriptions(rows)
          })

        return answer
    #---------------------------------------------------------------------------
    def extract (self, debug=False, format=dict):
        answer = []

        answer += self.extractBySimilarity(items=self.byManaged.items(),
            attribute="managed", similarity="Managed Policies", format=format)

        answer += self.extractBySimilarity(items=self.byMembers.items(),
            attribute="members", similarity="Group Membership", format=format)

        answer += self.extractBySimilarity(items=self.byInlinePolicy.items(),
            attribute="policy", similarity="Inline Policies", format=format)

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def canonicalizePolicy (policy):
        """
        Canonicalize an inline policy for comparison. Serializes to JSON with
        sorted keys so structurally identical policies produce the same string
        regardless of original key order or policy name.
        """
        if not policy:
            return None

        # policy may be a string (JSON) or a dict
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return None

        if not isinstance(policy, dict) or len(policy) == 0:
            return None

        # Extract just the policy documents, ignoring policy names
        # (two policies with different names but identical content are equivalent)
        documents = sorted(
            [json.dumps(v, sort_keys=True) for v in policy.values()]
            if isinstance(policy, dict) else [json.dumps(policy, sort_keys=True)]
        )

        return "|".join(documents)
    #---------------------------------------------------------------------------
    def keys (self, row=None):
        """
        Return the keys for managed policies, group members, and inline
        policies. Entities with no managed policies are considered similar,
        but entities with no members, including groups, are not considered
        similar. Inline policy keys compare canonical policy content,
        ignoring policy names.
        """
        managedKey = "|".join(sorted(row.managed)) \
            if row.managed else None
        membersKey = "|".join(sorted(row.members)) \
            if row.members and (row.entityType == "Group") else None
        policyKey = self.canonicalizePolicy(row.policy)

        return managedKey, membersKey, policyKey
################################################################################
# 
################################################################################
class SimilarityOutputRow:
    """
    Represent a similarity entity as a spreadsheet row or as a DynamoDb item.
    """
    def __init__ (self, reportDate=None, similarity=None, by=None,
        entities=None):
        """ See class definition for details """
        self.order = {
            "reportDate": "ReportDate",
            "id": "ReportRowId",
            "similarity": "SimilarityType",
            "by": "SimilarBy",
            "entities": "SimilarEntities"
        }

        self.reportDate = reportDate if reportDate\
            else datetime.datetime.now().isoformat()
        self.id = None
        self.similarity = similarity
        self.by = by
        self.entities = entities

        # Generate an ID from the reportDate, the similarity type, and the 
        # "similar by" list
        digest = hashlib.sha256()
        digest.update(bytes(str(self.by) + self.similarity + self.reportDate, "utf-8"))

        self.id = digest.hexdigest()
    #---------------------------------------------------------------------------
    def asDict (self, ttl=None):
        """
        Return the row as a Python dict which is suitable for a DynamoDb item.
        If writing to DynamoDb, you can optionally add a TTL value
        """
        answer = {
            "reportDate": self.reportDate,
            "id": self.id,
            "similarity": self.similarity,
            "by": self.by,
            "entities": self.entities
        }

        if ttl:
            answer["TTL"] = int(time.time() + ttl)

        return answer
    #---------------------------------------------------------------------------
    def asList (self, serialize=True, indent=None, header=False):
        """ 
        Return as a list for use in a CSV or spreadsheet context. Structured 
        data can be serialized, and you can request a CSV header instead of a
        a data row.
        """
        answer = []

        for attribute, columnName in self.order.items():
            if header:
                answer.append(columnName)
            else:
                if serialize and attribute in ["by", "entities"]:
                    value = pprint.pformat(getattr(self, attribute, []))
                else:
                    value = getattr(self, attribute, None)

                answer.append(value)

        return answer
################################################################################
# 
################################################################################
class IamOutputRow:
    """
    Represent an IAM entity as a spreadsheet row with columns representing the
    entity name, AWS account number, the type of entity, the members (groups), 
    the managed policy list, and the inline policies.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, reportDate=None, name=None, account=None, entityType=None, members=[], 
        managed=[], policy=None, description=None, arn=None):
        """ See the class definition for details. """
        self.id = None
        self.reportDate = reportDate if reportDate\
            else datetime.datetime.now().isoformat()
        self.name = name
        self.description = None
        self.account = account
        self.entityType = ugr
        self.members = members
        self.managed = managed
        self.policy = policy
        self.arn = arn if arn\
            else f'arn:aws:iam::{self.account}:{self.entityType.lower()}/{self.name}'

        # The ID is generated from the ARN and reportDate
        digest =  hashlib.sha256()
        digest.update(bytes(self.arn + self.reportDate, "utf-8"))

        self.id = digest.hexdigest()
    #---------------------------------------------------------------------------
    def asDict (self, ttl=None):
      """
      Return the row as a Pythin dict. If we are writing to a dynamodb table
      we can optionally add a TTL value.
      """
      answer = {
        "reportDate": self.reportDate,
        "id": self.id,
        "account": self.account,
        "type": self.entityType,
        "name": self.name,
        "arn": self.arn,
        "description": self.description,
        "members": self.members,
        "managed": self.managed,
        "policy": self.policy
      }

      if ttl:
        answer["TTL"] = int(time.time() + ttl)

      return answer
    #---------------------------------------------------------------------------
    def asList (self, serialize=True, indent=None, header=False):
        """
        Return the row as a Python (mutable) list, optionally serializing any
        structured data; by specifying indent you can format the serialized 
        data with indents and linefeeds.
        """
        if header:
            answer = [
                "ReportDate",
                "ReportItemId",
                "EntityName",
                "EntityArn",
                "EntityDescription",
                "EntityAccount",
                "EntityType",
                "EntityMembers",
                "EntityManaged",
                "EntityPolicy"
            ]
        else:
            answer = [ 
                self.reportDate,
                self.id,
                self.name ,
                self.arn,
                self.description ,
                self.account ,
                self.entityType ,
                self.members if not serialize\
                    else pprint.pformat(self.members),
                self.managed if not serialize\
                    else pprint.pformat(self.managed),
                self.policy if not serialize\
                    else pprint.pformat(self.policy)
            ]

        return answer
################################################################################
# 
################################################################################
class IamActor (cc.Actor):
    """
    Concrete implementation of abstract Actor class to collect IAM user, role, 
    and group entities. 
    """
    def __init__ (self, role=None, similar=None, region=None):
        """ See class definition for details. """
        super().__init__(service="iam", role=role, region=region)

        self.similar = similar
        self.users = IamUsers(client=self.client).download()
        self.roles = IamRoles(client=self.client).download()
        self.groups = IamGroups(client=self.client).download()
    #---------------------------------------------------------------------------
    def extract (self, format=list):
        """
        Returns a set of rows, one row for each user, group, and role entity
        identified when the object was instantiated.
        """
        answer = []
        entityParameters = [
            ("User", self.users, "userName") ,
            ("Group", self.groups, "groupName") ,
            ("Role", self.roles, "roleName")
        ]

        for _type, _list, _name in entityParameters:
            for entity in _list:
                row = IamOutputRow(
                    name=getattr(entity, _name),
                    account=self.accountId,
                    entityType=_type, 
                    members=entity.members,
                    managed=entity.managed,
                    policy=entity.policies
                )

                # Track similar rows
                self.similar.add(row)

                answer.append(row.asList() if format == list else row.asDict())

        return answer
################################################################################
# 
################################################################################
class SsoActor (cc.Actor):
    """
    Concrete implementation of abstract Actor class to collect Single Signon
    (SSO) permission set data. 
    """
    def __init__ (self, region=None, role=None):
        """ See class definition for details. """
        super().__init__(region=region, service="sso-admin", role=role)

        self.role = role
        self.account = re.search(r':(\d{12}):', role).group(1) if role else None
        self.region = region
        self.instances = {}
        self.sets = {}
    #---------------------------------------------------------------------------
    def listInstances (self):
        """
        Get a list of AWS SSO instances using the sso-admin:list_instance API
        """
        self.instances = {}

        try:
          instance = self.page(
            api=self.client.list_instances,
            fence="Instances"
          )

          for instance in instance:
            key = instance.get("InstanceArn")
            self.instances[key] = instance

        except botocore.exceptions.ClientError as thrown:
          if type(thrown).__name__ != "AccessDeniedException":
            raise thrown
            
          cc.emit("242020", "w", f'{self.role} access denied: {thrown}')

        return self
    #---------------------------------------------------------------------------
    def listSets (self):
        """
        List permission sets and their associated details.
        """
        self.sets = {}

        for instance in self.instances.keys():
          try:
            sets = self.page(
              api=self.client.list_permission_sets,
              fence="PermissionSets",
              additional={"InstanceArn": instance}
            )

            for setId in sets:
              self.sets[setId] = self.describeSet(instance, setId)

          except botocore.exceptions.ClientError as thrown:
            cc.emit("242030", "e", 
              f'list_permission_sets (region {self.region}: {thrown}')

        return self
    #---------------------------------------------------------------------------
    def describeSet (self, instance=None, permissionSet=None):
        """
        Get details about a permission set, including a list of managed policies
        and the inline policies associated with that set.
        """
        details = self.client.describe_permission_set(
            InstanceArn=instance,
            PermissionSetArn=permissionSet
        ).get("PermissionSet", {})

        managed = self.page(
            api=self.client.list_managed_policies_in_permission_set,
            fence="AttachedManagedPolicies",
            additional={"InstanceArn": instance, "PermissionSetArn": permissionSet}
        )

        inline = self.client.get_inline_policy_for_permission_set(
            InstanceArn=instance,
            PermissionSetArn=permissionSet
        ).get("InlinePolicy", {})

        details["AttachedManagedPolicies"] = \
            [ policy.get("Name") for policy in managed ]
        details["InlinePolicy"] = inline
        details["SsoInstanceArn"] = instance

        return details
    #---------------------------------------------------------------------------
    def permissionSets (self):
        """
        Get permission sets to which I have access
        """

        return self.listInstances().listSets().sets
################################################################################
# 
################################################################################
class AccountRowException (Exception):
    pass
################################################################################
# 
################################################################################
class SkipRow (Exception):
    pass
################################################################################
# 
################################################################################
class AccountRow:
    """
    Represents a row in the "AWS Accounts & Roles" sheet
    """
    #---------------------------------------------------------------------------
    @staticmethod
    def strint (value=None):
        """
        Convert whatever into the string representation of an integer, or None
        """
        try:
            answer = str(int(value))
        except:
            answer = None

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def toNone (value=None):
        """
        Convert strings of only whitespace to "None"
        """
        if value == None:
            answer = None
        elif len(value.strip()) == 0:
            answer = None
        else:
            answer = value
        
        return answer
    #---------------------------------------------------------------------------
    def __init__ (self, initializer=[]):
        """ See class description for details """
        cc.emit("242040", "d", f'initializer {initializer}')

        if len(initializer) < 6:
            raise AccountRowException("AccountRow initializer must be a list of length 6")

        self.accountId = "%012d" % int(initializer[0])
        self.nickname = AccountRow.toNone(initializer[1])
        self.role = AccountRow.toNone(initializer[2])
        self.partition = AccountRow.toNone(initializer[3]) 
        self.defaultRegion = AccountRow.toNone(initializer[4])
        self.ssoRegion = AccountRow.toNone(initializer[5])
    #---------------------------------------------------------------------------
    def record (self):
      """ Return serializable values """
      return vars(self)
################################################################################
# 
################################################################################
class GenericEncoder (JSONEncoder):
    def default (self, object):
        try:
            answer = object.__dict__
        except:
            answer = "[skipped property]"

        return answer
################################################################################
# 
################################################################################
class ParseRowException (Exception):
    pass
################################################################################
# 
################################################################################
class ParseRow:
    _ACCOUNT_STRIP = re.compile("\D")
    _ACCOUNT_PATTERN = re.compile("^(?P<accountId>\d{12})$")
    _ROLE_PATTERN = re.compile("^arn:(?P<partition>aws[-\w]*):iam::" + 
        "(?P<accountId>\d{12}|\*):role/(?P<roleName>.*)$")
    #---------------------------------------------------------------------------
    def __init__ (self, columns={}, row=[]):
        self.columns = columns
        self.row = row

        self.accountId = self.getAccountId(row, columns.get("accountColumn", 1))
        self.role, self.rolePartition, self.roleAccountId = \
            self.getRole(row, columns.get("roleColumn", 2))
        self.pattern = self.getPattern(row, columns.get("patternColumn", 3))
    #---------------------------------------------------------------------------
    def getAccountId (self, row=[], column=None):
        value = ParseRow._ACCOUNT_STRIP.sub("", self.row[column-1])
        match = ParseRow._ACCOUNT_PATTERN.match(value)

        if not match:
            raise ParseRowException("ParseRow did not find a valid account ID " + \
                "(%s) in column %d" % (value, column))

        answer = match.group('accountId')

        return answer
    #---------------------------------------------------------------------------
    def getRole (self, row=[], column=None):
        match = ParseRow._ROLE_PATTERN.match(row[column-1])

        if not match:
            role = None
            partition = None
            accountId = None
        else:
            role = match.group(0)
            partition = match.group("partition")
            accountId = match.group("accountId")

        if accountId == "*":
            role = re.sub(re.compile(":\*:role\/"), ":%s:role\/" % 
                self.accountId, role)
        elif role and (accountId != self.accountId):
            raise ParseRowException("ParseRow role accountId %s is not " + 
                "'*' and does not match target accountId %s" % 
                (accountId, self.accountId))

        return (role, partition, accountId)
    #---------------------------------------------------------------------------
    def getPattern (self, row=[], column=None):
        try:
            _ = re.compile(row[column-1])

            answer = row[column-1]
        except Exception as thrown:
            answer = None

        return answer
    #---------------------------------------------------------------------------
    def valid (self):
        return ParseRow._ACCOUNT_PATTERN.match(self.accountId)
