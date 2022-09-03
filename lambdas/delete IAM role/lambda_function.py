import os
import boto3
import botocore
import logging
import json

aws_service = "iam"
implementation_service="cloudformation"
target_region="us-east-1"
logger = logging.getLogger()
stack_name="amuda"

def lambda_handler(event, context):
    sts = boto3.client("sts")  
    account_num = sts.get_caller_identity()["Account"]
    logger.info(f"Starting scan of new account {account_num}")
    logger.info(f"account_num: {account_num}")
    role_arn = f"arn:aws:iam::{account_num}:role/GoDaddy_assumed_role"
    sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
    credentials = sts_auth["Credentials"]
    
    # ----------------------------- #
    # Place all service code below
    # ----------------------------- #

    # Section for boto3 connection with aws service
    sts_client = boto3.client(implementation_service,
                            region_name=target_region,
                            aws_access_key_id=credentials["AccessKeyId"],
                            aws_secret_access_key=credentials["SecretAccessKey"],
                            aws_session_token=credentials["SessionToken"], )
                        
    response =sts_client.delete_stack(
        StackName=stack_name,
        ClientRequestToken='GodaddyDelete'
    )
    
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:       

        res = {
                "accountData": account_num,
                "deleteData": {
                "service": aws_service,
                "status": "iam roles deleted"
                }
        }
        logger.info(f"RESPONSE: {res}")
        return res

    else:
        return("failed to delete roles")            