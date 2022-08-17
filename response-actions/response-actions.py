import json
from datetime import datetime, timedelta
from time import sleep
import smtplib
import dateutil.parser
import os
import argparse
from jinja2 import Template
from httplib2 import Http
from oauth2client import tools
from oauth2client.service_account import ServiceAccountCredentials
from apiclient import discovery
import boto3
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from botocore.exceptions import ClientError
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
logging.getLogger().setLevel(logging.INFO)

SECRET_NAME = config['AWS']['SECRET_NAME']
REGION_NAME = config['AWS']['REGION_NAME']
ADMIN_EMAIL = config['GCP']['ADMIN_EMAIL']
TABLE_NAME = config.get('AWS', 'TABLE_NAME')
SENDER = config['GCP']['SENDER']


with open("adminNotification.html.j2", "r") as t:
    ADMIN_NOTIFICATION = t.read()

with open("userNotification.html.j2", "r") as t:
    USER_NOTIFICATION = t.read()

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
            decoded_binary_secret = base64.b64decode(
                get_secret_value_response["SecretBinary"]
            )

    return json.loads(secret)


def get_credentials(owner):
    '''Assume delegated access of user account in order to take file actions'''
    scopes = ["https://www.googleapis.com/auth/drive"]
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
        get_secret(), scopes=scopes, token_uri=None, revoke_uri=None
    )
    delegated_credentials = credentials.create_delegated(owner)
    return delegated_credentials


def deletePermission(owner, fileId, permissionId):
    '''Use Google Drive API to delete the specific file permission that was in violation of the policy. This only deletes ONE permission (i.e. domain sharing), not all file permissions.'''
    credentials = get_credentials(owner)
    http = credentials.authorize(Http())
    api = discovery.build("drive", "v3", http=http)

    try:
        results = (
            api.permissions().delete(fileId=fileId, permissionId=permissionId).execute()
        )
        logging.info(f"Deleted permission {permissionId} for {fileId}")
        return True
    except Exception as e:
        logging.info(f"Permission cannot be deleted {e}")
        return "deletion-error"


def sendMail(event, template, recipient):
    '''Send email notification to admin or user'''
    SUBJECT = "[Notification] Google DLP violation of {} policy detected in {}".format(
        event["triggeredPolicy"], event["resourceName"]
    )
    BODY_HTML = Template(template).render(event=event)
    CHARSET = "UTF-8"

    client = boto3.client("ses", region_name=REGION_NAME)

    try:
        response = client.send_email(
            Destination={
                "ToAddresses": [
                    recipient,
                ],
            },
            Message={
                "Body": {
                    "Html": {
                        "Charset": CHARSET,
                        "Data": BODY_HTML,
                    }
                },
                "Subject": {
                    "Charset": CHARSET,
                    "Data": SUBJECT,
                },
            },
            Source=SENDER,
        )
    except ClientError as e:
        logging.info(e.response["Error"]["Message"])
        return "mail-error"
    else:
        return "success"


def updateDbStatus(
    eventData,
    actionsComplete,
    adminNotificationSent,
    userNotificationSent,
    permissionsRevoked,
):
    dynamodb = boto3.resource("dynamodb", region_name=REGION_NAME)
    table_name = TABLE_NAME
    table = dynamodb.Table(table_name)

    response = table.update_item(
        Key={"uniqueId": eventData["uniqueId"]},
        UpdateExpression="set actionsComplete = :a, adminNotificationSent = :n, userNotificationSent = :u, permissionsRevoked = :p",
        ExpressionAttributeValues={
            ":a": actionsComplete,
            ":n": adminNotificationSent,
            ":u": userNotificationSent,
            ":p": permissionsRevoked,
        },
        ReturnValues="UPDATED_NEW",
    )

    return response


def main(event, context):
    '''For events with policy decisions, take the defined response actions associated with the violated policy.'''

    for record in event.get("Records"):
        if record.get("eventName") == "MODIFY":
            deserializer = TypeDeserializer()
            eventData = {
                k: deserializer.deserialize(v)
                for k, v in record["dynamodb"]["NewImage"].items()
            }
            actionsComplete = eventData.get("actionsComplete", False)
            logging.info(eventData)
            if actionsComplete == False:
                userNotificationSent = False
                adminNotificationSent = False
                permissionsRevoked = False
                for action in eventData["responseActions"]:
                    if action == "Send admin notification":
                        try:
                            response = sendMail(
                                eventData, ADMIN_NOTIFICATION, ADMIN_EMAIL
                            )
                            adminNotificationSent = True
                        except:
                            raise
                    if action == "Send user notification":
                        try:
                            response = sendMail(
                                eventData,
                                USER_NOTIFICATION,
                                eventData["resourceOwnerEmail"],
                            )
                            if response == "success":
                                userNotificationSent = True
                        except:
                            logging.info(f"Permission not revoked for permission {eventData['violatedPermissionId']} for file {eventData['resourceId']} owned by user {eventData['resourceOwnerEmail']}")
                    if action == "Revoke access":
                        try:
                            deletePermission(
                                eventData["resourceOwnerEmail"],
                                eventData["resourceId"],
                                eventData["violatedPermissionId"],
                            )
                            permissionsRevoked = True
                        except:
                            raise
                actionsComplete = True
                updateDbStatus(
                    eventData,
                    actionsComplete,
                    adminNotificationSent,
                    userNotificationSent,
                    permissionsRevoked,
                )
