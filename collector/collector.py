import json
import os
from datetime import datetime, timedelta
from time import sleep
import boto3
import googleapiclient.errors
from apiclient import discovery
from httplib2 import Http
from oauth2client import tools
from oauth2client.service_account import ServiceAccountCredentials
import botocore.exceptions
from botocore.exceptions import ClientError
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

logging.getLogger().setLevel(logging.INFO)


REPORT_SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
DIRECTORY_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]

TABLE_NAME = config.get('AWS', 'TABLE_NAME')
SECRET_NAME = config.get('AWS', 'SECRET_NAME')
REGION_NAME = config.get('AWS', 'REGION_NAME')
APPLICATION_NAME = config.get('APP', 'APPLICATION_NAME')
HISTORIC_WINDOW = config.getint('APP', 'HISTORIC_WINDOW')


class RuleEvent:
    def __init__(
        self,
        unique_id,
        event_time,
        matched_detectors,
        rule_name,
        resource_id,
        resource_owner_email,
        resource_recipients,
        actor_email,
        resource_name,
    ):
        self.unique_id = unique_id
        self.event_time = event_time
        self.matched_detectors = matched_detectors
        self.rule_name = rule_name
        self.resource_id = resource_id
        self.resource_owner_email = resource_owner_email
        self.resource_recipients = resource_recipients
        self.actor_email = actor_email
        self.resource_name = resource_name


class App:
    def __init__(self, adminApi, historic_window):
        self.adminApi = adminApi
        self.historic_window = historic_window

    def insertDynamoDb(self, bulkItems):
        '''Add activity logs containing detectpr information to DynamoDb'''
        dynamodb = boto3.resource("dynamodb", region_name=REGION_NAME)
        table = dynamodb.Table(TABLE_NAME)

        # authorize to google directory to get OU data
        api = get_credentials(DIRECTORY_SCOPES, "directory_v1")

        for item in bulkItems:
            try:
                table.put_item(
                    Item={
                        "uniqueId": item.unique_id,
                        "eventTimestamp": item.event_time,
                        "matchedDetectors": item.matched_detectors,
                        "ruleName": item.rule_name,
                        "resourceId": item.resource_id,
                        "resourceOwnerEmail": item.resource_owner_email,
                        "resourceRecipients": item.resource_recipients,
                        "actorEmail": item.actor_email,
                        "actorOU": get_OU(api, item.actor_email),
                        "ownerOU": get_OU(api, item.resource_owner_email),
                        "resourceName": item.resource_name,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    },
                    ConditionExpression="attribute_not_exists(uniqueId)",
                )
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise

        return

    def getDetailedPermissions(self, resource_owner_email, resource_id):
        '''For each file with sensitive data detected, use the Google Drive API to retrieve detailed file permissions settings'''
        logging.info("Getting detailed permissions for {}".format(resource_owner_email))

        try:
            driveApi = get_user_credentials(resource_owner_email)
        except:
            #This exception will occur on external user or Team Drive permissions checks
            logging.warning(f"Resource owner {resource_owner_email} not in domain")

        permissionList = []

        try:
            results = (
                driveApi.permissions()
                .list(fileId=resource_id, fields="*", supportsAllDrives="true")
                .execute()
            )
            while results is not None:
                nextPage = results.get("nextPageToken")
                permissions = results.get("permissions", [])
                for permission in permissions:
                    permissionList.append(
                        {
                            # type can be domain, group, user, anyone
                            "type": permission.get("type", "null"),
                            # role can be reader, viewer, writer, commenter, owner, organizer, fileOrganizer
                            "role": permission.get("role", "null"),
                            # whether file is searchable - only applies to type: domain or anyone
                            "allowFileDiscovery": permission.get(
                                "allowFileDiscovery", "null"
                            ),
                            # only exists for user type
                            "emailAddress": permission.get("emailAddress", "null"),
                            # should exist for all types
                            "displayName": permission.get("displayName", "null"),
                            "id": permission.get("id", "null"),
                        }
                    )
                if nextPage is None:
                    break
                else:
                    results = (
                        driveApi.permissions()
                        .list(
                            fileId=resource_id,
                            fields="*",
                            supportsAllDrives="true",
                            pageToken=nextPage,
                        )
                        .execute()
                    )
        except:
            logging.info(f"File {resource_id} not found")
        return permissionList

    def get_events(self):
        '''Get all DLP rules events within the HISTORIC_WINDOW range. Reducing this range can improve performance but risks missing events.'''
        logging.info("Getting events")
        start, end = time_bucket_range(historic_window=self.historic_window)

        logging.info(f"Results from {start} to {end}")
        # Get activities list for tokens
        results = (
            self.adminApi.activities()
            .list(
                userKey="all",
                applicationName="rules",
                filters="rule_type==dlp",
                startTime=start.isoformat() + "Z",
                endTime=end.isoformat() + "Z",
                maxResults="500",
            )
            .execute()
        )

        # process data as long as there are results to process
        while results is not None:
            # get user list and page token
            activities = results.get("items", [])
            nextPage = results.get("nextPageToken")
            bulkItems = []

            for activity in activities:
                try:
                    detectorData = next(
                        item
                        for item in activity["events"][0]["parameters"]
                        if item["name"] == "matched_detectors"
                    )["multiMessageValue"][0]["parameter"]
                    matched_detectors = next(
                        item for item in detectorData if item["name"] == "detector_id"
                    )["value"]

                except:
                    # if no detectors, move on to next rule activity
                    continue

                unique_id = activity["id"]["uniqueQualifier"]
                resource_id = next(
                    item
                    for item in activity["events"][0]["parameters"]
                    if item["name"] == "resource_id"
                )["value"]
                resource_owner_email = next(
                    item
                    for item in activity["events"][0]["parameters"]
                    if item["name"] == "resource_owner_email"
                )["value"]
                resource_recipients = self.getDetailedPermissions(
                    resource_owner_email, resource_id
                )
                event_time = activity["id"]["time"]
                rule_name = next(
                    item
                    for item in activity["events"][0]["parameters"]
                    if item["name"] == "rule_name"
                )["value"]
                actor_email = activity["actor"].get("email", "Not found")
                resource_name = next(
                    item
                    for item in activity["events"][0]["parameters"]
                    if item["name"] == "resource_title"
                )["value"]

                eventItem = RuleEvent(
                    unique_id=unique_id,
                    event_time=event_time,
                    matched_detectors=matched_detectors,
                    rule_name=rule_name,
                    resource_id=resource_id,
                    resource_name=resource_name,
                    resource_owner_email=resource_owner_email,
                    resource_recipients=resource_recipients,
                    actor_email=actor_email,
                )

                bulkItems.append(eventItem)

            self.insertDynamoDb(bulkItems=bulkItems)
            logging.info(f"\nBulk inserted {len(bulkItems)} items into DynamoDb")
            # if there are no more results, end program
            if nextPage is None:
                break
            # otherwise get next set
            else:
                try:
                    results = (
                        self.adminApi.activities()
                        .list(
                            userKey="all",
                            applicationName="rules",
                            filters="rule_type==dlp",
                            startTime=start.isoformat() + "Z",
                            endTime=end.isoformat() + "Z",
                            maxResults="500",
                            pageToken=nextPage,
                        )
                        .execute()
                    )
                except googleapiclient.errors.HttpError:
                    logging.info(
                        "Error occurred on Google API. Sleeping for a bit before trying again."
                    )
                    sleep(10)


def time_bucket_range(historic_window):
    end = datetime.utcnow()
    start = end - timedelta(minutes=historic_window)

    return start, end


def get_secret():

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=REGION_NAME)

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
        else:
            secret = base64.b64decode(
                get_secret_value_response["SecretBinary"]
            )

    return json.loads(secret)


def get_credentials(scopes, service):
    '''Create Google Admin delegated credentials for querying the admin API'''
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
        get_secret(), scopes=scopes, token_uri=None, revoke_uri=None
    )
    delegated_credentials = credentials.create_delegated(
        os.environ.get("DELEGATED_ADMIN")
    )
    http = delegated_credentials.authorize(Http())
    api = discovery.build("admin", service, http=http)
    return api


def get_OU(api, actor):
    '''Determine which Google OU the user is in'''
    try:
        results = api.users().get(userKey=actor).execute()
        return results["orgUnitPath"]
    except:
        return "Not in domain"


def get_user_credentials(resource_owner_email):
    '''Create delegated user credentials in order to query Drive metadata on the users' behalf'''
    scopes = ["https://www.googleapis.com/auth/drive.metadata.readonly"]
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
        get_secret(), scopes=scopes, token_uri=None, revoke_uri=None
    )
    delegated_credentials = credentials.create_delegated(resource_owner_email)
    http = delegated_credentials.authorize(Http())
    api = discovery.build("drive", "v3", http=http)
    return api


def main(event, context):
    adminApi = get_credentials(REPORT_SCOPES, "reports_v1")

    app = App(adminApi=adminApi, historic_window=HISTORIC_WINDOW)

    app.get_events()

    return
