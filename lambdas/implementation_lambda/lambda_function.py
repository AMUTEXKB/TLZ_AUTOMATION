import json
import boto3 
import logging

logger = logging.getLogger()
client = boto3.client('stepfunctions')
modify_service="stepfunctions"
implementation_state_machine="KB_implementation_state_machine"
target_region="us_east_1"


def lambda_handler(event, context):
    sts = boto3.client("sts") 
    logger.info(f"REQUEST: {event}")
    target_region="us-east-1"
    account_num = sts.get_caller_identity()["Account"]        
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
    implementation_state_machine_arn=f"arn:aws:states:{target_region}:{account_num}:stateMachine:{implementation_state_machine}"
    response = sts_client.start_execution(
        stateMachineArn=implementation_state_machine_arn,
        input="{}")
    print(response)    
        
