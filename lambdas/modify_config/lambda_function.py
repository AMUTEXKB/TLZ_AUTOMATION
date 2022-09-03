import os
import boto3
import botocore
import logging

logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    aws_service = "config"
    config_name = "default" #input the parameters yourself
    kb_config_arn = "arn:aws:iam::672432851135:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    delivery_channel = "config-bucket-672432851135"
    dynamodbtable_name="TlsAutomationStack"

    try:
        account_num = sts.get_caller_identity()["Account"]
        target_region = "us-east-1"
        kb_central_logging_bucket = "config-bucket-672432851135"
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
                                  region_name=target_region,
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
            Key={"service": {'S': aws_service}
            })
        if scan_data['Item']["service"] == {"S":aws_service} and scan_data['Item']["status"] == {"S":"disabled"}:   
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
                            "accountData": account_num,
                            "implementationData": {
                                "service":{ "S": aws_service},
                                "status":{ "S":'enabled'}
                            }
                        }

            logger.info(res)

            response = client.put_item(
                TableName=dynamodbtable_name,
                        Item=res["implementationData"]) 
        else:
        #if custom insight have not been created before create insight
            logger.info(f"service already enabled in {account_num} and {target_region}")

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
