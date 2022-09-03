import json
import os
import boto3
import botocore
import logging


def lambda_handler(event, context):
   
    sts = boto3.client("sts")
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.info(f"event: {event}")
    aws_service = "config"
    target_region="us-east-1"
    account_id = sts.get_caller_identity()["Account"]
    
    logger.info("Starting delete of Account's Config")
    logger.info(f"account_num: {account_id}")
    role_arn = f"arn:aws:iam::{account_id}:role/KB_assumed_role" #create an assume role with the name KB_assumed_role
    sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
    credentials = sts_auth["Credentials"]

        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #

        # Section for boto3 connection with aws service
    sts_client = boto3.client(aws_service,
                              region_name=target_region,
                              aws_access_key_id=credentials["AccessKeyId"],
                              aws_secret_access_key=credentials["SecretAccessKey"],
                              aws_session_token=credentials["SessionToken"], )


    # Section for the "delete" boto3 code for AWS service
    #Get detailed info for config using recorder status
    response = sts_client.describe_configuration_recorder_status(
                   ConfigurationRecorderNames=[]
       )
    if len(response["ConfigurationRecordersStatus"]) > 0:
       for con in response["ConfigurationRecordersStatus"]:
                    
           config = {
                            "name": con["name"],
                            "recording": con["recording"],
                           
                          }  
                          
           dean=con["name"] 
    else:
        error_message = "Config detail fetch failed!"
        logger.error(error_message)
        raise Exception(error_message)
    
    if dean!= "":
       response = sts_client.delete_configuration_recorder(
       ConfigurationRecorderName=dean
)
       if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
          status = f"Config {dean} deleted for Account Number: {account_id}"
          res = {
            "accountData": {
                "accountId": account_id
            },
            "deleteData": {
                "service": "config",
                "configName": dean,
            },
            "status": status
        }
          return res
       else:
            raise Exception("Unable to delete Config")
  
    else:
        error_message = "Config detail fetch failed!"
        logger.error(error_message)
        raise Exception(error_message)
  