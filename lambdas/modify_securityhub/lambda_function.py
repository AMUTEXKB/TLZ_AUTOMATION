import json
import boto3
import re
import botocore
import logging
import os

logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    region= event["region"]
    print(f"scanData: {region}")
    tablename="TlsAutomationStack"
    account_num = sts.get_caller_identity()["Account"]
    aws_service = "securityhub"
    try:
        logger.info(f"Starting implementation for new account {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName = "acquired_account_role")
        credentials=sts_auth["Credentials"]

# ----------------------- #
# Place all service code below
# ----------------------- #

        # Section for boto3 connection with aws service
        sts_sec_hub_client = boto3.client(aws_service,
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],)
        d_client = boto3.client('dynamodb')
        scan_data= d_client.get_item(
                TableName=tablename,
                Key={"region":{"S":region},
                    "service": {'S': aws_service}
                })
        if scan_data['Item']["region"] == {"S":region} and scan_data["Item"]["service"] == {"S":aws_service} and scan_data['Item']["status"] == {"S":"disabled"}:     
            enable_sh = sts_sec_hub_client.enable_security_hub(EnableDefaultStandards=True)
            get_new_info = sts_sec_hub_client.describe_hub()
            sh_info = get_new_info["HubArn"]
            if re.search("arn:aws:securityhub:*", sh_info):
                return {
                    "region":region,
                    "accountData": account_num,
                    "implementationData": {
                        "region":{"S":region},
                        "service": {"S":aws_service},
                        "status":{"S": "Security Hub is enabled"}
                    }
                }
            else:
                return {
                    "region":region,
                    "accountData": account_num,
                    "implementationData": {
                        "region":{"S":region},
                        "service":{"S": aws_service},
                        "status": {"S":"Unable to enable Security Hub"}
                    }
                }
        else:
            return {
                "region":region,
                "accountData": account_num,
                "implementationData": {
                    "region":{"S":region},
                    "service": {"S":aws_service},
                    "status":{"S": "Security Hub is already enabled"}
                }
            }

    except botocore.exceptions.ClientError as error:
        print(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn=f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message=f"An error has occurred during the implementation process of account {account_num}. The error is: {error_message}",
            Subject=f"Error occurred in running implementation of {aws_service} on account {account_num}."
        )
        raise
