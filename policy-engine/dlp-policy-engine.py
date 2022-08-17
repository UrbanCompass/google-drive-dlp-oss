import json
import boto3
import botocore.exceptions
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
import os
import logging
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
logging.getLogger().setLevel(logging.INFO)
DOMAIN = config['APP']['DOMAIN']
TABLE_NAME = config.get('AWS', 'TABLE_NAME')
REGION_NAME = config.get('AWS', 'REGION_NAME')

with open("dlp-policies.json") as f:
    DLPPOLICIES = json.load(f)


def evaluatePermissions(event):
    '''Evaluates event and file metadata (OU, matched detectors, file permissions) against policy definitions to check for violation'''
    print(
        "Evaluating permissions for {} {}".format(
            event["resourceOwnerEmail"], event["uniqueId"]
        )
    )
    if "ownerOU" not in event:
        return ["No action required - No matches found"], "none", "none"
    if event['ownerOU'] == "Not in domain":
        return ['No action required - Not in domain'], 'none', 'none'
    if DOMAIN not in event["resourceOwnerEmail"]:
        return ["No action required - Not in domain"], "none", "none"
    for policy in DLPPOLICIES["policies"]:
        # evaluate further if detector & user OU matches
        detectorMatch = False
        print(event["matchedDetectors"])
        if event["matchedDetectors"] in policy["matchedDetectors"]:
            detectorMatch = True
            logging.info(
                "Detector match found for {}".format(event["resourceOwnerEmail"])
            )
        # get root OU
        rootOU = event["ownerOU"].split("/")[1]
        # if detector and OU match then evaluate the rest of the metadata
        if (detectorMatch == True) and (
            event["ownerOU"] in policy["ous"]
            or policy["ous"] == ["*"]
            or rootOU in policy["ous"]
        ):
            # check policy definition against event metadata for each recipient permission
            for recipient in event["resourceRecipients"]:
                keyCount = len(policy) - 5
                matchCount = 0
                for key in policy:
                    if key in [
                        "type",
                        "role",
                        "allowFileDiscovery",
                        "recipientDisplayName",
                    ]:
                        if policy[key] == recipient[key]:
                            logging.info(
                                "Match found: {} {}".format(policy[key], recipient[key])
                            )
                            matchCount += 1
                        else:
                            logging.info(
                                "Match not found, check next recipient: {} {}".format(
                                    policy[key], recipient[key]
                                )
                            )
                    # if all keys match, return response actions & triggered policy
                    if matchCount == keyCount:
                        return (
                            policy["responseActions"],
                            policy["policyName"],
                            recipient["id"],
                        )

    # If no matches, no action required
    return ["No action required - No matches found"], "none", "none"


def updateDbOutcome(eventData, responseActions, triggeredPolicy, violatedPermissionId):
    '''Update dynamodb with outcome of policy analysis'''
    dynamodb = boto3.resource("dynamodb", region_name=REGION_NAME)
    table = dynamodb.Table(TABLE_NAME)

    response = table.update_item(
        Key={"uniqueId": eventData["uniqueId"]},
        UpdateExpression="set responseActions = :r, triggeredPolicy = :t, violatedPermissionId = :v",
        ExpressionAttributeValues={
            ":r": responseActions,
            ":t": triggeredPolicy,
            ":v": violatedPermissionId,
        },
        ReturnValues="UPDATED_NEW",
    )

    return response


def main(event, context):
    '''Get unprocessed events from table'''

    for record in event.get("Records"):
        if record.get("eventName") == "INSERT":
            deserializer = TypeDeserializer()
            eventData = {
                k: deserializer.deserialize(v)
                for k, v in record["dynamodb"]["NewImage"].items()
            }
            # evaluate policies
            try:
                (
                    responseActions,
                    triggeredPolicy,
                    violatedPermissionId,
                ) = evaluatePermissions(eventData)
            except:
                responseActions = ["processingError"]
                raise

            # update ddb
            updateDbOutcome(
                eventData, responseActions, triggeredPolicy, violatedPermissionId
            )
