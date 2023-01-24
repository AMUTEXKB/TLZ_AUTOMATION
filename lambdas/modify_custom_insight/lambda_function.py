import os
import boto3
import botocore
import logging
import json
 
logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")  
    account_num = sts.get_caller_identity()["Account"]
    target_region=""
    insight_name=""
    aws_service="" 
    modify_service=""
    dynamodbtable_name=""
    sts = boto3.client("sts")
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
        if os.environ.get("insight_name") is not None:
            insight_name = os.environ.get("insight_name")
        else:
            error_message = "Missing environment variable insight_name"
            logger.error(error_message)
            raise Exception(error_message)
        if os.environ.get("dynamodbtable_name") is not None:
            dynamodbtable_name = os.environ.get("dynamodbtable_name")
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
        if os.environ.get("modify_service") is not None:
            modify_service = os.environ.get("modify_service")
        else:
            error_message = "Missing environment variable modify_service"
            logger.error(error_message)
            raise Exception(error_message)             
        region=event["region"] 
        client = boto3.client('dynamodb')
        logger.info(f"Starting scan of new account {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role" #create an assume role with the name KB_assumed_role
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]
    
        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #
    
        # Section for boto3 connection with aws service
        sts_client = boto3.client(modify_service,
                                  region_name=region,
                                  aws_access_key_id=credentials["AccessKeyId"],
                                  aws_secret_access_key=credentials["SecretAccessKey"],
                                  aws_session_token=credentials["SessionToken"], )
        
        #checking for already existing custom insight with same name
    
        response = sts_client.get_insights()
        if len(response["Insights"]) > 0:
            for insight in response["Insights"]:
                if  insight["Name"] == insight_name:
                    existing_arn= insight["InsightArn"]
                #updating existing custom insight
                    response = sts_client.update_insight(
                                                InsightArn=existing_arn, 
                                                Name= insight_name,
                                                Filters= {
                                                    "SeverityNormalized": [{"Gte": 70.0}],
                                                    "ProductFields": [
                                                        {
                                                            "Key": "ProductName",
                                                            "Value": "KBSCAN",
                                                            "Comparison": "EQUALS",
                                                        },
                                                    ],
                                                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                                                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                                                },
                                                GroupByAttribute= "ResourceType", )
                    res={
                        "enabledServices": "enabled_services",
                        "region":region,
                        "accountData": "account_data",
                        "implementationData": {
                        "region":{"S":region},
                        "service":{ "S": aws_service },
                        "status":{"S": "custom insight created successfully in securityhub"}
                    }}
                            
                else:
                #if custom insight have not been created before create insight                  
                    response = sts_client.create_insight(
                                                Name= insight_name,
                                                Filters= {
                                                    "SeverityNormalized": [{"Gte": 70.0}],
                                                    "ProductFields": [
                                                        {
                                                            "Key": "ProductName",
                                                            "Value": "KBSCAN",
                                                            "Comparison": "EQUALS",
                                                        },
                                                    ],
                                                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                                                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                                                },
                                                GroupByAttribute= "ResourceType",)
                    res={
                        "enabledServices": "enabled_services",
                        "region":region,
                        "accountData": account_num,
                        "implementationData": {
                            "region":{"S":region},
                            "service":{ "S": aws_service },
                            "status":{"S": "custom insight created successfully in securityhub"}
                        }
                    } 

            else:
            #if custom insight have not been created before create insight                  
                response = sts_client.create_insight(
                                            Name= insight_name,
                                            Filters= {
                                                "SeverityNormalized": [{"Gte": 70.0}],
                                                "ProductFields": [
                                                    {
                                                        "Key": "ProductName",
                                                        "Value": "KBSCAN",
                                                        "Comparison": "EQUALS",
                                                    },
                                                ],
                                                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                                                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                                            },
                                            GroupByAttribute= "ResourceType",)
                res={
                    "enabledServices": "enabled_services",
                    "region":region,
                    "accountData": account_num,
                    "implementationData": {
                        "region":{"S":region},
                        "service":{ "S": aws_service },
                        "status":{"S": "custom insight created successfully in securityhub"}
                    }
                }
        else:
            #if custom insight have not been created before create insight                  
            response = sts_client.create_insight(
                                        Name= insight_name,
                                        Filters= {
                                            "SeverityNormalized": [{"Gte": 70.0}],
                                            "ProductFields": [
                                                {
                                                    "Key": "ProductName",
                                                    "Value": "KBSCAN",
                                                    "Comparison": "EQUALS",
                                                },
                                            ],
                                            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                                            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                                        },
                                        GroupByAttribute= "ResourceType",)
            res={
                "enabledServices": "enabled_services",
                "region":region,
                "accountData": account_num,
                "implementationData": {
                    "region":{"S":region},
                    "service":{ "S": aws_service },
                    "status":{"S": "custom insight created successfully in securityhub"}
                }
            }
        response = client.put_item(
            TableName=dynamodbtable_name,
                    Item=res["implementationData"]) 
        return(res)                   
                                                              
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