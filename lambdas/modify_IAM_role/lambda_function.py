import os
import boto3
import botocore
import logging
import json


logger = logging.getLogger()
stack_name="role"
# stack parameters



def lambda_handler(event, context):
    sts = boto3.client("sts") 
    modify_service = "cloudformation"
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    target_region="us-east-1"
    account_num = sts.get_caller_identity()["Account"]
    aws_service="iam"
    dynamodbtable_name="TlsAutomationStack"
    d_client = boto3.client('dynamodb')
    bucket_name="amudarole"

    stack_name="role"
    # stack parameters
    deploy_version="2010-09-09"
    audit_account_role_arns=f"arn:aws:iam::{account_num}:user/Jahmai-Training-User"
    audit_account_param_buckets="arn:aws:s3:::amudakb"
    audit_account_result_buckets="arn:aws:s3:::amudakb"
    
    scan_data= d_client.get_item(
            TableName=dynamodbtable_name,
            Key={"service": {'S': aws_service}
            })
    if scan_data['Item']["service"] == {"S":aws_service} and scan_data['Item']["status"] == {"S":"disabled"}:  
        client = boto3.client("organizations")
        
        response = client.describe_account(
        AccountId=account_num
        )
        email=response['Account']['Email']
        
    
        logger.info(f"Starting modify of new account: {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role" #create an assume role with the name KB_assumed_role
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
        
        stack_result = launch_stack(
            sts_client,
            stack_name,
            deploy_version,
            audit_account_role_arns,
            audit_account_param_buckets,
            audit_account_result_buckets,
            email,account_num,aws_service,
            bucket_name
        )

        res = {
                "accountData": account_num,
                "implementationData": {
                    "service":{ "S": aws_service},
                    "status":{ "S":'enabled'}
                }
            }

        logger.info(res)

        response = d_client.put_item(
            TableName=dynamodbtable_name,
                    Item=res["implementationData"])
    else:
        logger.info(f"{aws_service} already enabled in {account_num} and {target_region}")                     

def launch_stack(client,
                stack_name,
                deploy_version,
                audit_account_role_arns,
                audit_account_param_buckets,
                audit_account_result_buckets,
                email,account_num,aws_service,
                bucket_name):


    try:

    
        logger.info(f"Creating {stack_name}")
        s3_client = boto3.client("s3")
        presigned_url = s3_client.generate_presigned_url(
                            "get_object", {
                                "Bucket": bucket_name,
                                "Key": f"{stack_name}.yml"
                            }, ExpiresIn = 900)  
        client.create_stack(
            StackName=stack_name,
            TemplateURL=presigned_url,
            Parameters=[
                {
                    'ParameterKey': 'DeployVersion',
                    'ParameterValue': deploy_version
                },            {
                    'ParameterKey': 'AuditAccountRoleArns',
                    'ParameterValue': audit_account_role_arns
                },            {
                    'ParameterKey': 'AuditAccountParamBuckets',
                    'ParameterValue': audit_account_param_buckets
                },            {
                    'ParameterKey': 'AuditAccountResultsBuckets',
                    'ParameterValue': audit_account_result_buckets
                },            {
                    'ParameterKey': 'SecurityDL',
                    'ParameterValue': email
                }
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"]
        )
        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #
    
        # Section for boto3 connection with aws service
        res = {
            "accountData": account_num,
            "implementationData": {
                "service":{ "S": aws_service},
                "status":{ "S":'enabled'},
                "deploy_started":{ "S":"True"}
                }
            }

        logger.info(res)

    except botocore.exceptions.ClientError as error:
        logger.error(f"Launch Stack Error: {error}")
        if error.response["Error"]["Code"] == "AlreadyExistsException":
            res = {
                "accountData": account_num,
                "implementationData": {
                    "service":{ "S": aws_service},
                    "status":{ "S":'enabled'},
                    "deploy_started":{ "S":"False"}
                    }
                }
            logger.info(res)
        raise