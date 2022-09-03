import os
import boto3
import botocore
import logging
import json

logger = logging.getLogger()

def lambda_handler(event, context):
    insight_name="" 
    modify_service=""
    tablename=""
    aws_service="" 
    target_region=""
    sts = boto3.client("sts")
    account_num = sts.get_caller_identity()["Account"]
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
   
 
    try:
        if os.environ.get("target_region") is not None:
            target_region = os.environ.get("target_region")
        else:
            error_message = "Missing environment variable target_region"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("insight_name") is not None:
            insight_name = os.environ.get("insight_name")
        else:
            error_message = "Missing environment variable insight_name"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("tablename") is not None:
            tablename = os.environ.get("tablename")
        else:
            error_message = "Missing environment variable tablename"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("modify_service") is not None:
            modify_service = os.environ.get("modify_service")
        else:
            error_message = "Missing environment variable modify_service"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("aws_service") is not None:
            aws_service = os.environ.get("aws_service")
        else:
            error_message = "Missing environment variable aws_service"
            logger.error(error_message)
            raise Exception(error_message)   

        logger.info(f"Starting scan of new account {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]
    
        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #
    
        # Section for boto3 connection with aws service
        sts_client = boto3.client(modify_service,
                                  region_name=target_region,
                                  aws_access_key_id=credentials["AccessKeyId"],
                                  aws_secret_access_key=credentials["SecretAccessKey"],
                                  aws_session_token=credentials["SessionToken"], )
        
        #checking for already existing custom insight with same name
        
        response = sts_client.get_insights()
        if  len(response["Insights"]) > 0:
            for insight in response["Insights"]:
                if  insight["Name"] == insight_name:
                    existing_arn= insight["InsightArn"]
                #updating existing custom insight
                    res= {
                                "enabledServices": "enabled_services",
                                "accountData": "account_data",
                                "scanData": {
                                    "service":{"S": aws_service},
                                    "status": {"S":"enabled"}
                                }
                            }
                    print(res)
                else:
                    res= {
                            "enabledServices": "enabled_services",
                            "accountData": "account_data",
                            "scanData": {
                                "service":{"S": aws_service},
                                "status": {"S":"disabled"}
                            }
                        }
                    print(res)
                    
        else:
            res= {
                "enabledServices": "enabled_services",
                "accountData": "account_data",
                "scanData": {
                            "service":{"S": aws_service},
                            "status": {"S":"disabled"}
                }
                    }
            print(res)

        client = boto3.client('dynamodb')    
        response = client.put_item(
            TableName=tablename,
            Item=res["scanData"])

        return res        
    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn = f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the scanning process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occured in running scan of {aws_service} on account {account_num}."
        )
        raise