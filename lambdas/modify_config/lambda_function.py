import os
import boto3
import botocore
import logging

logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")
    account_num = sts.get_caller_identity()["Account"]
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    aws_service = ""
    config_name = ""
    kb_config_arn = f"arn:aws:iam::{account_num}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    dynamodbtable_name=""
    target_region = ""
   

    try:
        if os.environ.get("target_region") is not None:
            target_region = os.environ.get("target_region")
        else:
            error_message = "Missing environment variable target_region"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("config_name") is not None:
            config_name= os.environ.get("config_name")
        else:
            error_message = "Missing environment variable config_name"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("dynamodbtable_name") is not None:
            dynamodbtable_name = os.environ.get("dynamodbtable_name")
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
        region=event["region"]     
        client = boto3.client('dynamodb')

        logger.info(f"Starting scan of new account {account_num}")
        logger.info(f"account_num: {account_num}")
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
        # Section for the "get" or "describe" boto3 code for AWS service
             # ----------------------------- #
        # Place all service code below
        # ----------------------------- #

        # Section for boto3 connection with aws service
        scan_data= client.get_item(
            TableName=dynamodbtable_name,
            Key={"region":{"S":region},
                "service": {'S': aws_service}
            })
        if scan_data['Item']["region"] == {"S":region} and scan_data["Item"]["service"] == {"S":aws_service} and scan_data['Item']["status"] == {"S":"disabled"}:      
            create_recorder = sts_client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": config_name,
                "roleARN": kb_config_arn,
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": False,

            }
        })
            # section for creating config delivery channel

            # section for starting config recorder
            response = sts_client.start_configuration_recorder(
            ConfigurationRecorderName=config_name,
    )

            res = {
                            "enabledServices": 'enabled_services',
                            "region":region,
                            "accountData": account_num,
                            "implementationData": {
                                "region":{"S":region},
                                "service":{ "S": aws_service},
                                "status":{ "S":'enabled'}
                            }
                        }

            logger.info(res)

            
        else:
        #if custom insight have not been created before create insight
            logger.info(f"service already enabled in {account_num} and {target_region}")
            res = {
                "enabledServices": 'enabled_services',
                "region":region,
                "accountData": account_num,
                "implementationData": {
                    "region":{"S":region},
                    "service":{ "S": aws_service},
                    "status":{ "S":'enabled'}
                }
            }
        response = client.put_item(
            TableName=dynamodbtable_name,
                    Item=res["implementationData"]) 
        return (res)            

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
