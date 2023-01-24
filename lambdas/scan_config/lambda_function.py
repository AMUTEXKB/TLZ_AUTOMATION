import os
import boto3
import botocore
import logging

def lambda_handler(event, context):
    sts = boto3.client("sts")
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.info(f"event: {event}")
    aws_service = ""
    enabled_services = "enabledServices"
    region=event["region"]
    target_region=""
    tablename=""
    account_num = sts.get_caller_identity()["Account"]
    try:
        if os.environ.get("target_region") is not None:
            target_region = os.environ.get("target_region")
        else:
            error_message = "Missing environment variable target_region"
            logger.error(error_message)
            raise Exception(error_message)

        if os.environ.get("tablename") is not None:
            tablename = os.environ.get("tablename")
        else:
            error_message = "Missing environment variable tablename"
            logger.error(error_message)
            raise Exception(error_message)

        if os.environ.get("aws_service") is not None:
            aws_service = os.environ.get("aws_service")
        else:
            error_message = "Missing environment variable aws_service"
            logger.error(error_message)
            raise Exception(error_message)  

        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]

            # ----------------------------- #
            # Place all service code below
            # ----------------------------- #

            # Section for boto3 connection with aws service
        sts_client = boto3.client(aws_service,
                                    region_name=region,
                                    aws_access_key_id=credentials["AccessKeyId"],
                                    aws_secret_access_key=credentials["SecretAccessKey"],
                                    aws_session_token=credentials["SessionToken"], )
        # ----------------------------- #
            # Place all service code below
            # ----------------------------- #

        
            # Section for the "get" or "describe" boto3 code for AWS service                        
        response = sts_client.describe_delivery_channels(
            DeliveryChannelNames=[])
        if len(response["DeliveryChannels"]) > 0:
            for cong in response["DeliveryChannels"]:
                conf= {'s3BucketName': cong['s3BucketName'],}
            
        else:
            logger.info(f"config is disabled. Account Num: account_num")
            res= {
                    "enabledServices": enabled_services,
                    "region":region,
                    "accountData": 'account_data',
                    "scanData": {
                        "region":{"S":region},
                        "service":{"S": aws_service},
                        "status": {"S":"disabled"}
                    }
                }
            print(f"RESPONSE: {res}")
            

            #Get detailed info for config using recorder status
        response = sts_client.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[])
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            if len(response["ConfigurationRecordersStatus"]) > 0:
                for con in response["ConfigurationRecordersStatus"]:
                            
                    config = {
                                    "name": con["name"],
                                    "recording": con["recording"],
                                    's3BucketName': cong['s3BucketName'],
                                }  
            
                    status = "enabled" if con["recording"]== True else "disabled" 
                
                res= {
                        "region":region,                        
                        "scanData": {
                             "region":{"S":region},
                            "service":{"S": aws_service},                         
                            "status":{"S": status},
                            
                            's3BucketName':{"S":cong['s3BucketName']},
                        }}
                

            else:
                logger.info(f"config is disabled. Account Num: account_num")
                res= {
                        "enabledServices": enabled_services,
                        "region":region, 
                        "accountData": 'account_data',
                        "scanData": {
                            "region":{"S":region},
                            "service":{"S": aws_service},
                            "status": {"S":"disabled"}
                        }
                    }
                print(f"RESPONSES: {res}")
            

        else:
            logger.info(f"config is disabled. Account Num: account_num")
            res = {
                    "enabledServices": enabled_services,
                    "region":region, 
                    "accountData": 'account_data',
                    "scanData": {
                        "region":{"S":region},
                        "service":{"S": aws_service},
                        "status": {"S":"disabled"}
                    }
                }
            print(f"RESPONSE: {res}")

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