import json
from urllib.request import urlopen
import os
import boto3
import botocore
import logging

logger = logging.getLogger()
def lambda_handler(event, context):
    file_name=""
    bucket_name=""

    if os.environ.get("bucket_name") is not None:
        bucket_name= os.environ.get("bucket_name")
    else:
        error_message = "Missing environment variable bucket_name"
        logger.error(error_message)
        raise Exception(error_message)
    if os.environ.get("file_name") is not None:
        file_name = os.environ.get("file_name")
    else:
        error_message = "Missing environment variable file_name"
        logger.error(error_message)
        raise Exception(error_message)                   

    sts = boto3.client("sts")
    logging.basicConfig(level=logging.INFO)
   
    logger.info(f"event: {event}")
    aws_service = "stepfunctions"
    account_id = sts.get_caller_identity()["Account"]
    logger.info("Starting scan stepfunctions")
    logger.info(f"account_num: {account_id}")
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
    s3_client = boto3.client("s3")
    presigned_url = s3_client.generate_presigned_url(
                        "get_object", {
                            "Bucket": bucket_name,
                            "Key": f"{file_name}.json"
                        }, ExpiresIn = 900) 
    print(presigned_url)                    

    response = urlopen(presigned_url)
    file = json.loads(response.read())
    response = sts_client.start_execution(
        stateMachineArn='arn:aws:states:us-east-1:672432851135:stateMachine:testing',
        input=json.dumps(file)
    )
    print(response)    