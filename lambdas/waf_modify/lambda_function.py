import os
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
    aws_service = "wafroles"
    modify_service = "cloudformation"
    try:
     
        account_num = ""
        target_region = ""
        stack_name = "" 
        bucket_name = ""
        deploy_version = "2010-09-09"
        godaddy_web_acl_v2="GoDaddyDefaultWebACLv2"
        
        #validate event and env var 
        #validate event and env var
        if "accountData" in event:
            account_data = event["accountData"]
        else:
            error_message = "Missing parameter accountData"
            logger.error(error_message)
            raise Exception(error_message)
        if "accountId" in event["accountData"]:
            account_num = account_data["accountId"]
        else:
            error_message = "Missing parameter accountId"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("target_region") is not None:
            target_region = os.environ.get("target_region")
        else:
            error_message = "Missing environment variable target_region"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("stack_name") is not None:
            stack_name = os.environ.get("stack_name")
        else:
            error_message = "Missing environment variable stack_name"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("bucket_name") is not None:
            bucket_name = os.environ.get("bucket_name")
        else:
            error_message = "Missing environment variable bucket_name"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("deploy_version") is not None:
            deploy_version = os.environ.get("deploy_version")
        else:
            error_message = "Missing environment variable deploy_version"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("godaddy_web_acl_v2") is not None:
            godaddy_web_acl_v2 = os.environ.get("godaddy_web_acl_v2")
        else:
            error_message = "Missing environment variable godaddy_web_acl_v2"
            logger.error(error_message)
            raise Exception(error_message)



        logger.info(f"Starting creation of new WAF roles: {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/GoDaddy_assumed_role"#input your own assume role
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

        logger.info("PRE LAUNCH STACK")
        # Section for the "get" or "describe" boto3 code for AWS service
        stack_result = launch_stack(
            sts_client,
            stack_name,
            bucket_name,
            deploy_version,
            godaddy_web_acl_v2,
        )

        logger.info(f"Cfn Stack Result: {stack_result}")

        return event

    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn = f"arn:aws:sns:{target_region}:{account_num}:GD_Send_Failure_Notification_Topic",
            Message = f"An error has occurred during the create process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occurred in running {aws_service} on account {account_num}."
        )
        raise
 
def launch_stack(sts_client,
                 stack_name,
                 bucket_name,
                 deploy_version,
                 godaddy_web_acl_v2,
): 
    try:
        logger.info(f"Creating {stack_name}")
        s3_client = boto3.client("s3")
        presigned_url = s3_client.generate_presigned_url(
                            "get_object", {
                                "Bucket": bucket_name,
                                "Key": f"{stack_name}.yml"
                            }, ExpiresIn = 900)
        sts_client.create_stack(
            StackName=stack_name,
            TemplateURL=presigned_url,
            Parameters=[
                {
                    'ParameterKey': 'DeployVersion',
                    'ParameterValue': deploy_version
                },            {
                    'ParameterKey': 'GodaddyWebACLv2',
                    'ParameterValue': godaddy_web_acl_v2
                }, 
      
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"] 
        )
        res = {
            "status": "Pending"
        }
        return res

    except botocore.exceptions.ClientError as error:
        logger.error(f"Launch Stack Error: {error}")
        if error.response["Error"]["Code"] == "AlreadyExistsException":
            res = {
                "status": "enabled"
            }
            return res
        raise
