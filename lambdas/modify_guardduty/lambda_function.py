import os
import json
import boto3
import re
import botocore
import logging
import time 
from time import sleep
import boto3
from botocore.config import Config

logger = logging.getLogger()
guardduty_logging_bucket_name ="amudakb" 
target_region = "us-east-1"
dynamodbtable_name="TlsAutomationStack"

def lambda_handler(event, context):
    sts = boto3.client("sts")
    enabled_services ="enabledServices"
    aws_service = "guardduty"
    guardduty_logging_bucket_name ="amudakb"
    destination_bucket_arn = f"arn:aws:s3:::{guardduty_logging_bucket_name}"
    try:
        account_num = sts.get_caller_identity()["Account"]        
        account_data = account_num
        target_region = "us-east-1"

        logger.info(f"Starting implementation of guardduty in the new account {account_num}")
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
        client = boto3.client('dynamodb')                                  
        scan_data= client.get_item(
            TableName=dynamodbtable_name,
            Key={"service": {'S': aws_service}
            })                                  
        if scan_data['Item']["service"] == {"S":aws_service} and scan_data['Item']["status"] == {"S":"disabled"}:         
            sts_client.create_detector(Enable=True)

            get_new_info = sts_client.list_detectors()
            detector_id = (get_new_info["DetectorIds"])

            if not detector_id:
                return {
                    "enabledServices": enabled_services,
                    "accountData": account_data,
                    "implementationData": {
                        "service": aws_service,
                        "status": "Unable to enable GuardDuty",
                        "detectorId": "not found",
                        "destinationBucketArn": "not found"
                    }
                }
            else:
                destination_bucket_arn = get_detector_s3_publish_destination(credentials, target_region, auto_acct, account_num, detector_id[0],
                                                                            guardduty_logging_bucket_name)
                return {
                    "enabledServices": enabled_services,
                    "accountData": account_data,
                    "implementationData": {
                        "service": aws_service,
                        "status": "Guard Duty is enabled",
                        "detectorId": detector_id[0],
                        "destinationBucketArn": destination_bucket_arn
                    }
                }
        else:
            return {
                "enabledServices": enabled_services,
                "accountData": account_data,
                "implementationData": {
                    "service": aws_service,
                    "status": "Guard Duty is already enabled",
                    "detectorId": "not found",
                    "destinationBucketArn": "not found"
                }
            }
    except botocore.exceptions.ClientError as error:
        # Section for how to deal with error exceptions that might occur
        print(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn= f"arn:aws:sns:{target_region}:{account_num}:KB_Send_Failure_Notification_Topic",
            Message= f"An error has occurred during the implementation process of account {account_num}. The error is: {error_message}",
            Subject= f"Error occurred in running implementation of {aws_service} on account {account_num}."
            )
        # TO-DO: send an SNS message about the error
        raise


def get_detector_s3_publish_destination(credentials, target_region, auto_acct, account_num, detector_id, guardduty_logging_bucket_name):
    try:
        gd_client = boto3.client("guardduty",
                                 aws_access_key_id=credentials["AccessKeyId"],
                                 aws_secret_access_key=credentials["SecretAccessKey"],
                                 aws_session_token=credentials["SessionToken"])

        get_findings_dest = gd_client.list_publishing_destinations(DetectorId=detector_id)
        destinations = get_findings_dest["Destinations"]
        print(f"Destinations: {destinations}")
        if destinations:
            for destination in destinations:
                destination_type = destination["DestinationType"]
                if destination_type == "S3":
                    destination_id = destination["DestinationId"]
                    print(f"DestinationId: {destination_id}")
                    publishing_destination = gd_client.describe_publishing_destination(
                        DetectorId=detector_id,
                        DestinationId=destination_id
                    )
                    destination_properties = publishing_destination["DestinationProperties"]
                    print(f"DestinationId: {destination_id}")
                    return destination_properties["DestinationArn"]
                else:
                    create_s3_publishing_destination(credentials, account_num, detector_id, guardduty_logging_bucket_name)
                    print("done")
        else:
            create_s3_publishing_destination(credentials, account_num, detector_id, guardduty_logging_bucket_name)
            
    except Exception as error:
        print(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish(
            TopicArn=f"arn:aws:sns:{target_region}:{account_num}:KB_Send_Failure_Notification_Topic",
            Message=f"An error has occurred get/create publishing destination {error_message}",
            Subject="Error occurred in get/create publishing destination."
        )
        raise


def create_s3_publishing_destination(credentials, account_num, detector_id, guardduty_logging_bucket_name):
    gd_client = boto3.client("guardduty",
                             aws_access_key_id=credentials["AccessKeyId"],
                             aws_secret_access_key=credentials["SecretAccessKey"],
                             aws_session_token=credentials["SessionToken"])

    bucket_arn = f"arn:aws:s3:::{guardduty_logging_bucket_name}"

    guard_duty_kms_key = create_guard_duty_kms_key(credentials, account_num)
    print(f"guard_duty_kms_key: {guard_duty_kms_key}")


    gd_client.create_publishing_destination(
        DetectorId=detector_id,
        DestinationType="S3",
        DestinationProperties={
            "DestinationArn": bucket_arn,
            "KmsKeyArn": guard_duty_kms_key
        })

    return bucket_arn


def create_guard_duty_kms_key(credentials, account_num):
    try:
        kms_client = boto3.client("kms",
                                  aws_access_key_id=credentials["AccessKeyId"],
                                  aws_secret_access_key=credentials["SecretAccessKey"],
                                  aws_session_token=credentials["SessionToken"])
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_num}:root"
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [f"arn:aws:iam::{account_num}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                            f"arn:aws:iam::{account_num}:role/KB_assumed_role"]
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": "*"
            },
            {
                "Sid": "AllowGuardDutyKey",
                "Effect": "Allow",
                "Principal": {
                    "Service": "guardduty.amazonaws.com"
                },
                "Action": [
                    "kms:GenerateDataKey",
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:DescribeKey"
                ],
                "Resource": f"arn:aws:kms:*:{account_num}:key/*"
            },
            {
                "Sid": "AllowS3AccessDutyKey",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": [
                    "kms:GenerateDataKey",
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:DescribeKey"
                ],
                "Resource": f"arn:aws:kms:*:{account_num}:key/*"
            },
            ]
        })
        iam = boto3.resource('iam')
        role= iam.Role('AWSServiceRoleForAmazonGuardDuty')
        role.load() 
        
        response = kms_client.create_key(
            Policy=policy,
            Description="Guard Duty S3 Destination KMS Key",
            KeyUsage="ENCRYPT_DECRYPT"
    
        )
    
        return response["KeyMetadata"]["Arn"]
    except botocore.exceptions.ClientError as error:
        #check for this error as the service role may not be set up yet and run the function again
        if error.response["Error"]["Code"] == "MalformedPolicyDocumentException":
            return create_guard_duty_kms_key(credentials, account_num)
        else:
            raise
