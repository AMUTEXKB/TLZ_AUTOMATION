import json
import os
import boto3
import botocore
import logging

logger = logging.getLogger()
def lambda_handler(event, context):
   
    sts = boto3.client("sts")
    logging.basicConfig(level=logging.INFO)
   
    logger.info(f"event: {event}")
    aws_service = "organizations"
    account_id = sts.get_caller_identity()["Account"]
    logger.info("Starting scan stepfunctions")
    logger.info(f"account_num: {account_id}")
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/KB_assumed_role"
    sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
    credentials = sts_auth["Credentials"]

        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #

        # Section for boto3 connection with aws service
    sts_client = boto3.client(aws_service,
                              aws_access_key_id=credentials["AccessKeyId"],
                              aws_secret_access_key=credentials["SecretAccessKey"],
                              aws_session_token=credentials["SessionToken"], )
                       
    try:
        move_acct= sts_client.move_account(
            AccountId='449081201015',
            SourceParentId='ou-bish-j7mfxuat',
            DestinationParentId='ou-bish-7neva622')
        print(move_acct)

    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Message"] == "AccountNotFoundException":
           logger.info(f"account:{account_id} have all ready been moved or {account_id} does not exist in the organization")
           print(f"account:{account_id} have all ready been moved or {account_id} does not exist in the organization")     
        else:
            logger.error(f"Error: {error}")
            error_message = error.response["Error"]["Message"]
            sns_client = boto3.client("sns")
            sns_client.publish(
                TopicArn=f"arn:aws:sns:us-east-1:{account_id}:KB_Send_Failure_Notification_Topic",
                Message=f"An error has occurred during the scanning process of account {account_id} The error is: {error_message}",
                Subject=f"Error occurred in running scan of {aws_service} on account {account_id}." 
            )
            raise  
