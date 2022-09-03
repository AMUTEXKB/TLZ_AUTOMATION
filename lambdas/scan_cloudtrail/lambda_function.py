import json
import boto3
import botocore
import logging
import os


def lambda_handler(event, context):
    tablename=""
    target_region=""
    sts = boto3.client("sts")
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.info(f"event: {event}")
    aws_service = ""
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

        logger.info("Starting delete of Account's Config")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role" #create an assume role with the name KB_assumed_role
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]
        sts_client = boto3.client(aws_service,
                                region_name=target_region,
                                aws_access_key_id=credentials["AccessKeyId"],
                                aws_secret_access_key=credentials["SecretAccessKey"],
                                aws_session_token=credentials["SessionToken"], )
        
        # Section for the "get" or "describe" boto3 code for AWS service
        cloudtrails = sts_client.list_trails()
        logger.info(f"List of CloudTrails: {cloudtrails}")

        status = ""

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
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                if len(response["trailList"]) > 0:
                    for trail in response["trailList"]:
                        cloudtrail = {
                            "name": trail["Name"],
                            "s3BucketName": trail["S3BucketName"],
                            "isMultiRegionTrail": trail["IsMultiRegionTrail"],
                            "homeRegion": trail["HomeRegion"],
                            "isOrganizationTrail": trail["IsOrganizationTrail"]
                        }
                        cloudtrail_list.append(cloudtrail)
                        get_trail_status = sts_client.get_trail_status(
                            Name=trail["TrailARN"])
                        status = "enabled" if get_trail_status['IsLogging'] == True else "disabled"

                        res = {
                                "accountData": account_num,
                                "cloudTrailList": cloudtrail_list,
                                "scanData": {
                                    "service":{"S": aws_service},
                                    "status": {"S":status}
                                }
                        }
                        logger.info(f"{res}")
                        
            else:
                error_message = "CloudTrail detail fetch failed!"
                logger.error(error_message)
                raise Exception(error_message)

        
        else:
            logger.info(f"CloudTrail is disabled. Account Num: {account_num}")
            status = "disabled"
            res = {
                "accountData": account_num,
                "cloudTrailList": cloudtrail_list,
                "scanData": {
                    "service":{"S": aws_service},
                    "status":{"S": status}
                        }
                }
            logger.info(f"{res}")    

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
    
