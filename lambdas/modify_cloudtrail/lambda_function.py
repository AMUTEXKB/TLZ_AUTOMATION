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
    aws_service = "cloudtrail"
    try:
        account_num = sts.get_caller_identity()["Account"]
        target_region = "us-east-1"
        kb_cloudtrail_name = ""
        kb_central_logging_bucket = ""
        kb_cloudtrail_logging_prefix = ""
        kb_cloudtrail = {}


        logger.info(f"Starting modify of new account: {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/config_lambda"
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
        cloudtrails = sts_client.list_trails()
        logger.info(f"List of Cloudtrails: {cloudtrails}")

        if len(cloudtrails) > 0:
            #build list of trail arns to use for describe_trails()
            cloudtrail_arn_list = []
            for cloudtrail in cloudtrails["Trails"]:
                cloudtrail_arn_list.append(cloudtrail["TrailARN"])

            #Get detailed info for trails using list of arns
            response = sts_client.describe_trails(
                trailNameList=cloudtrail_arn_list,
                includeShadowTrails=True
            )
            cloudtrail_list = []
            kb_cloudtrail_logs = False
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                if len(response["trailList"]) > 0:
                    #print(f"trailList: {response['trailList']}")
                    for trail in response["trailList"]:
                        #s3 key prefix is optional and may not be set
                        s3_key_prefix = "" if "S3KeyPrefix" not in trail else trail["S3KeyPrefix"]
                        is_multi_region_trail = str(trail["IsMultiRegionTrail"]).lower()
                        is_organization_trail = str(trail["IsOrganizationTrail"]).lower()
                        cloudtrail = {
                            "name": trail["Name"],
                            "s3BucketName": trail["S3BucketName"],
                            "isMultiRegionTrail": is_multi_region_trail,
                            "homeRegion": trail["HomeRegion"],
                            "isOrganizationTrail": is_organization_trail
                        }
                        if s3_key_prefix != "":
                            cloudtrail["s3KeyPrefix"] = s3_key_prefix
                        cloudtrail_list.append(cloudtrail)

                        #check if trail is set to gd cloudtrail bucket
                        if trail["S3BucketName"] == kb_central_logging_bucket:
                            logger.info("KB CloudTrail Exists!")
                            kb_cloudtrail_logs = True
            else:
                error_message = "CloudTrail detail fetch failed!"
                logger.error(error_message)
                raise Exception(error_message)

            if kb_cloudtrail_logs == False:
                #no gd cloudtrail exist for this account so we"ll create
                kb_cloudtrail = create_cloudtrail(sts_client, kb_cloudtrail_name, kb_central_logging_bucket, kb_cloudtrail_logging_prefix)
                if "error" in trail:
                    raise Exception(response["error"])
                event_selectors = create_cloudtrail_event_selectors(sts_client, kb_cloudtrail["trailName"])
                if "error" in event_selectors:
                        raise Exception(response["error"])
                start_logging = start_cloudtrail_logging(sts_client, kb_cloudtrail["trailARN"])
                if "error" in start_logging:
                        raise Exception(response["error"])

        else:
            logger.info(f"CloudTrail is currently disabled. Creating new CloudTrail for Account Number: {account_num}")
            kb_cloudtrail = create_cloudtrail(sts_client, kb_cloudtrail_name, kb_central_logging_bucket, kb_cloudtrail_logging_prefix)
            if "error" in trail:
                    raise Exception(response["error"])
            event_selectors = create_cloudtrail_event_selectors(sts_client, kb_cloudtrail["trailName"])
            if "error" in event_selectors:
                    raise Exception(response["error"])
            start_logging = start_cloudtrail_logging(sts_client, kb_cloudtrail["trailARN"])
            if "error" in start_logging:
                    raise Exception(response["error"])

        if kb_cloudtrail_logs == False:
            #add new cloudtrail to existing list
            cloudtrail = {
                "name": kb_cloudtrail["trailName"],
                "s3BucketName": kb_cloudtrail["s3Bucket"],
                "s3KeyPrefix": kb_cloudtrail["s3KeyPrefix"],
                "isMultiRegionTrail": kb_cloudtrail["isMultiRegionTrail"],
                "isOrganizationTrail": kb_cloudtrail["isOrganizationTrail"]
            }
            cloudtrail_list.append(cloudtrail)

        res = {
            "accountData": account_num,
            "implementationData": {
                "service": aws_service,
                "cloudTrailList": cloudtrail_list,
                "status": f"CloudTrail enabled for Account Number: {account_num}"
            }
        }
        return res


    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn =f"arn:aws:sns:us-east-1:{account_num}:kb_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the modify process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occurred in running modify of {aws_service} on account {account_num}."
        )
        raise

def create_cloudtrail(client, kb_cloudtrail_name, kb_cloudtrail_destination, kb_cloudtrail_destination_prefix):
    response = client.create_trail(
        Name=kb_cloudtrail_name,
        S3BucketName=kb_cloudtrail_destination,
        S3KeyPrefix=kb_cloudtrail_destination_prefix,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        IsOrganizationTrail=False
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:

        is_multi_region_trail = str(response["IsMultiRegionTrail"]).lower()
        is_organization_trail = str(response["IsOrganizationTrail"]).lower()
        return {
            "trailName": response["Name"],
            "s3Bucket": response["S3BucketName"],
            "s3KeyPrefix": response["S3KeyPrefix"],
            "isMultiRegionTrail": is_multi_region_trail,
            "isOrganizationTrail": is_organization_trail,
            "trailARN": response["TrailARN"]
        }
    else:
        return {"error": "CloudTrail creation failed!"}

def create_cloudtrail_event_selectors(client, trail_name):
    response = client.put_event_selectors(
        TrailName=trail_name,
        EventSelectors=[
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": ["arn:aws:s3:::"]
                    }
                ]
            }
        ]
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        return response
    else:
        return {"error": "CloudTrail event selectors creation failed!"}

def start_cloudtrail_logging(client, trail_name):
    response = client.start_logging(
        Name=trail_name
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        return response
    else:
        return {"error": "CloudTrail start logging failed!"}