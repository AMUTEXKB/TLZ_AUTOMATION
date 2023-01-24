import os
import json
import boto3
import botocore
import logging

logger = logging.getLogger()
target_region=""
def lambda_handler(event, context):
    sts = boto3.client("sts")
    logger.info(f"REQUEST: {event}")
    enabled_services = "enabledServices"
    account_num = sts.get_caller_identity()["Account"]  
    aws_service = ""
    region=event["region"]    
    findings_bucket ="" 
    destination_bucket_arn = f"arn:aws:s3:::{findings_bucket}"
    tablename=""

    try:
        if os.environ.get("target_region") is not None:
            target_region = os.environ.get("target_region")
        else:
            error_message = "Missing environment variable target_region"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("findings_bucket") is not None:
            findings_bucket = os.environ.get("findings_bucket")
        else:
            error_message = "Missing environment variable findings_bucket"
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

        logger.info(f"Starting scan of new account {account_num}")
        print(f"account_num: {account_num}")
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
        get_info = sts_client.list_detectors()
        detector_id = (get_info["DetectorIds"])
        if detector_id:
            logger.info(f"Guard Duty is enabled. Account Num: {account_num}")
            destination_bucket_arn = get_detector_s3_publish_destination(credentials, account_num, detector_id[0],
                                                                         findings_bucket)
            res= {
                "enabledServices": enabled_services,
                "region":region,
                "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status": {"S":"enabled"},
                    "detectorId":{"S": detector_id[0]},
                    "destinationBucketArn":{"S": destination_bucket_arn}
                },

            }
        else:
            logger.info(f"Guard Duty is disabled. Account Num: {account_num}")
            res={
                "enabledServices": enabled_services,
                "region":region,
                "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status": {"S":"disabled"},
                    "detectorId":{"S": "not found"},
                    "destinationBucketArn": {"S":"not found"}
                }
            }

    except botocore.exceptions.ClientError as error:
        errorMatch = f"Account {account_num} is not subscribed to Guard Duty Hub"
        if error.response["Error"]["Message"] == errorMatch:
            logger.info(f"Guard Duty is disabled.")

            res = {
                "enabledServices": enabled_services,
                "region":region,
                 "scanData": {
                    "region":{"S":region},
                    "service":{"S": aws_service},
                    "status": {"S":"disabled"},
                    "detectorId": {"S":"not found"},
                    "destinationBucketArn": {"S":"not found"}
                }
            }
        

        else:
            logger.error(f"Error: {error}")
            error_message = error.response["Error"]["Message"]
            sns_client = boto3.client("sns")
            sns_client.publish(
                TopicArn=F"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
                Message=f"An error has occurred during the scanning process of account {account_num} The error is: {error_message}",
                Subject=f"Error occurred in running scan of {aws_service} on account {account_num}."
            )
            raise
    client = boto3.client('dynamodb')    
    response = client.put_item(
        TableName=tablename,
        Item=res["scanData"])
    return (res)     

def get_detector_s3_publish_destination(credentials, account_num, detector_id, findings_bucket):
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
                    return create_s3_publishing_destination(credentials, account_num, detector_id, findings_bucket)
        else:
            return create_s3_publishing_destination(credentials, account_num, detector_id, findings_bucket)
    except Exception as error:
        print(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish(
            TopicArn=f"arn:aws:sns:{target_region}:{account_num}:KB_Send_Failure_Notification_Topic",
            Message=f"An error has occurred get/create publishing destination {error_message}",
            Subject="Error occurred in get/ create publishing destination."
        )
        raise


def create_s3_publishing_destination(credentials, account_num, detector_id, findings_bucket):
    gd_client = boto3.client("guardduty",
                             aws_access_key_id=credentials["AccessKeyId"],
                             aws_secret_access_key=credentials["SecretAccessKey"],
                             aws_session_token=credentials["SessionToken"])

    bucket_arn = f"arn:aws:s3:::{findings_bucket}"

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
    kms_client = boto3.client("kms",
                              aws_access_key_id=credentials["AccessKeyId"],
                              aws_secret_access_key=credentials["SecretAccessKey"],
                              aws_session_token=credentials["SessionToken"])

    policy = json.dumps(
        {
            "Id": "key-policy",
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Allow use of the key",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_num}:root"
                    },
                    "Action": [
                        "kms:*"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "Allow use of the key",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_num}:role/GoDaddy_assumed_role"
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
                    "Action": "kms:GenerateDataKey",
                    "Resource": "*",
                }
            ]
        }
    )

    print(f"ksm_policy: {policy}")

    response = kms_client.create_key(
        Policy=policy,
        Description="Guard Duty S3 Destination KMS Key",
        KeyUsage="ENCRYPT_DECRYPT",
    )

    return response["KeyMetadata"]["Arn"]


def is_service_enabled(enabled_services, service):
    return service in enabled_services
