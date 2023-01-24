import json
import boto3
import logging
import botocore
import os

logger = logging.getLogger()
def lambda_handler(event, context):
    aws_service="guardduty"
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


        logger.info(f"Starting delete of guardduty in {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
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
        
        get_info = sts_client.list_detectors()
        detector_id =get_info["DetectorIds"]
        print(detector_id)
        if detector_id:
            logger.info(detector_id)
            response = sts_client.delete_detector(
                DetectorId=detector_id[0]
            )
            res = {
                "accountData": {
                    "accountId": account_num
                },
                    "deleteData": {
                    "service": aws_service,
                    "status": "guardduty disabled"
                    }
            }
        else:
            res = {
                "accountData": {
                    "accountId": account_num
                },
                "deleteData": {
                "service": aws_service,
                "status": "guardduty already disabled"
                }
            }
        return(res)     
    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish(
            TopicArn =f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the delete config process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occurred in running delete of {aws_service} on account {account_num}."
        )
        raise
