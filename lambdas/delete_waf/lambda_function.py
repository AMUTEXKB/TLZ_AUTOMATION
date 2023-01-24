import os
import boto3
import botocore
import logging
import json

aws_service = "waf"
implementation_service="cloudformation"
target_region=""
logger = logging.getLogger()
stack_name=""


def lambda_handler(event, context):

    if os.environ.get("target_region") is not None:
        target_region = os.environ.get("target_region")
    else:
        error_message = "Missing environment variable target_region"
        logger.error(error_message)
        raise Exception(error_message)

    if os.environ.get("stack_name") is not None:
        stack_name = os.environ.get("stack_name")
    else:
        error_message = "Missing environment variable stack_name"
        logger.error(error_message)
        raise Exception(error_message)         

    try:
        sts = boto3.client("sts")  
        account_num = sts.get_caller_identity()["Account"]
        logger.info(f"Starting scan of new account {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]
        
        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #

        # Section for boto3 connection with aws service
        sts_client = boto3.client(implementation_service,
                                aws_access_key_id=credentials["AccessKeyId"],
                                aws_secret_access_key=credentials["SecretAccessKey"],
                                aws_session_token=credentials["SessionToken"], )
                            
        response =sts_client.delete_stack(
            StackName=stack_name
        )
        
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:       

            res = {
                    "accountData": {
                    "accountId": account_num},
                    "deleteData": {
                    "service": aws_service,
                    "status": "waf roles deleted"
                    }
            }
            logger.info(f"RESPONSE: {res}")
            return res

        else:
            return("failed to delete roles")     
    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish(
            TopicArn = f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the delete cloudtrail process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occurred in running delete of {aws_service} on account {account_num}."
        )
        raise
