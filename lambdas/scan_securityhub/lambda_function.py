import json
import boto3
import re
import botocore
import logging
import os

logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    region=event["region"]
    account_num = sts.get_caller_identity()["Account"]
    aws_service = "securityhub"
    tablename="TlsAutomationStack"
    try:
        logger.info(f"Starting scan of new account: {account_num}, service: {aws_service}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]

        # ----------------------- #
        # Place all service code below
        # ----------------------- #
        # Section for boto3 connection with aws service
        sts_sec_hub_client = boto3.client(aws_service,
                                          region_name=region,
                                          aws_access_key_id=credentials["AccessKeyId"],
                                          aws_secret_access_key=credentials["SecretAccessKey"],
                                          aws_session_token=credentials["SessionToken"], )

        #
        get_info = sts_sec_hub_client.describe_hub()
        sh_info = get_info["HubArn"]
        logger.info(sh_info)
        if re.search("arn*", str(sh_info)):
            logger.info(f"Security Hub is enabled. Account Num: {account_num}")
            response = {
                "region":region,
                "accountData": account_num,
                "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status": {"S":"enabled"}
                }
            }
        
        else:
            logger.info(f"Security Hub is disabled. Account Num: {account_num}")
            response = {
                "region":region,
                "accountData": account_num,
                "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status":{"S":"disabled"}
                }
            }
    
        client = boto3.client('dynamodb')    
        response = client.put_item(
            TableName=tablename,
            Item=response["scanData"])
        return (response)  

    except botocore.exceptions.ClientError as error:
        errorMatch = f"Account {account_num} is not subscribed to AWS Security Hub"
        if error.response["Error"]["Message"] == errorMatch:
            logger.info(f"Security Hub is disabled.")
            response = {
                "region":region,
                "accountData": account_num,
                "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status": {"S":"disabled"}
                }
            }
           
        else:
            logger.error(f"Error: {error}")
            error_message = error.response["Error"]["Message"]
            sns_client = boto3.client("sns")
            sns_client.publish(
                TopicArn=f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
                Message=f"An error has occurred during the scanning process of account {account_num}. The error is: {error_message}",
                Subject=f"Error occurred in running scan of {aws_service} on account {account_num}."
            )
            raise

    client = boto3.client('dynamodb')    
    response = client.put_item(
        TableName=tablename,
        Item=response["scanData"])
    return (response)          