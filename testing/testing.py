from pickle import FALSE
from typing import Mapping
import constructs as constructs
from aws_cdk import (
    # Duration,
    Stack,
    # aws_sqs as sqs,
    aws_s3 as _s3,
    aws_s3_deployment as s3deploy,
    aws_lambda as _lambda,
    Duration,
    aws_iam as _iam,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_apigateway as apigateway,
    aws_dynamodb as _dynamodb,
    aws_sns as _sns,
    aws_sns_subscriptions as _sns_subscriptions,
    aws_sqs as _sqs,
    aws_lambda_event_sources as SqsEventSource,
    triggers as triggers,
    RemovalPolicy,
    aws_cloudtrail as _cloudtrail,
    aws_events_targets as _targets,
    aws_logs as _logs,
    aws_cloudformation as _cloudformation,
    aws_config as config,CfnParameter,
)
from constructs import Construct

class Testing(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        upload_bucket_name = CfnParameter(self, "uploadBucketName", type="String",
            default="amudakb",
            description="The name of the Amazon S3 bucket where uploaded files will be stored.")  
        upload_file_name = CfnParameter(self, "uploadFileName", type="String",
            default="region",
            description="The name of the Amazon S3 object path where uploaded files will be stored.")  
      
        # Lambda Role Definitions

        security_scan_lambda_role = _iam.Role.from_role_arn(self, "SecurityScanLambdaRole",
                                                            "arn:aws:iam::109661032234:role/KB_assumed_role",

                                                            mutable=False)
        scan_config= _lambda.Function(self, "configScanLambdaFunction",
                                                       function_name="KB_scan_Config",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_config"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                                "aws_service":"config",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack"
                                                        },
                                                       role=security_scan_lambda_role)

        event_lambda= _lambda.Function(self, "unit_test",
                                            function_name="KB_unit_test_lambda",
                                            handler="lambda_function.lambda_handler",
                                            runtime=_lambda.Runtime.PYTHON_3_9,
                                            code=_lambda.Code.from_asset("lambdas/event_lambda"),
                                            timeout=Duration.seconds(10),
                                            role=security_scan_lambda_role)  

        start_scan_stepfunction= _lambda.Function(self, "StartScanStepFunction",
                                                       function_name="KB_start_scanstepfunction",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/start_stepfunction"),
                                                       timeout=Duration.seconds(10),
                                                       environment={"bucket_name":upload_bucket_name.value_as_string,
                                                                    "file_name":upload_file_name.value_as_string },
                                                       role=security_scan_lambda_role) 
        scan_iam_role=_lambda.Function(self, "IamRoleScanLambdaFunction",
                                                       function_name="KB_scan_IAM_role",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_IAM_role"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                                "stack_name":"amuda",
                                                                "modify_service":"cloudformation",
                                                                "aws_service":"iam",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack"
                                                        },
                                                       role=security_scan_lambda_role)
        scan_guardduty= _lambda.Function(self, "guarddutyScanLambdaFunction",
                                                       function_name="KB_scan_Guardduty",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_guard_duty"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                                "aws_service":"guardduty",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack",
                                                                "findings_bucket":"amudakb"
                                                        },
                                                       role=security_scan_lambda_role)                                                       
        scan_cloudtrail= _lambda.Function(self, "cloudtrailScanLambdaFunction",
                                                       function_name="KB_scan_Cloudtrail",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_cloudtrail"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                                "aws_service":"cloudtrail",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack"
                                                        },
                                                       role=security_scan_lambda_role)
        # scan_custom_insight= _lambda.Function(self, "custominsightScanLambdaFunction",
        #                                                function_name="KB_scan_Custom_Insight",
        #                                                handler="lambda_function.lambda_handler",
        #                                                runtime=_lambda.Runtime.PYTHON_3_9,
        #                                                code=_lambda.Code.from_asset(
        #                                                    "lambdas/scan_custom_insight"),
        #                                                timeout=Duration.seconds(10),
        #                                                environment={
        #                                                     "insight_name":"CIRRUSSCAN_INSIGHT_NAME",
        #                                                     "aws_service":"custom_insight", 
        #                                                     "modify_service":'securityhub',
        #                                                     "aws_service":"custom insight", 
        #                                                     "target_region":"us-east-1",
        #                                                     "tablename":"TlsAutomationStack"
        #                                                },
        #                                                role=security_scan_lambda_role) 
        scan_securityhub= _lambda.Function(self, "securityhubScanLambdaFunction",
                                                       function_name="KB_scan_securityhub",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_securityhub"),
                                                       timeout=Duration.seconds(10),
                                                       environment={
                                                            "tablename":"TlsAutomationStack"
                                                       },
                                                       role=security_scan_lambda_role) 
        call_update_lambda = _lambda.Function(self, "CallScansAPILambdaFunction",
                                            function_name="KB_Call_Scans_API",
                                            handler="lambda_function.lambda_handler",
                                            runtime=_lambda.Runtime.PYTHON_3_9,
                                            code=_lambda.Code.from_asset("lambdas/auto"),
                                            timeout=Duration.seconds(900),
                                            role=security_scan_lambda_role)                                                        

    # Scan Step functions Definition
        scan_config_lambda= tasks.LambdaInvoke(self, id="scan_config_lambda",
            lambda_function=scan_config,
            # Lambda's result is in the attribute `Payload`
        )
        scan_iam_role_lambda = tasks.LambdaInvoke(self, id="scan_iam_role",
            lambda_function=scan_iam_role,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        scan_securityhub_lambda = tasks.LambdaInvoke(self, id="scan_securityhub",
            lambda_function=scan_securityhub,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        scan_cloudtrail_lambda= tasks.LambdaInvoke(self, id="scan_cloudtrail",
            lambda_function=scan_cloudtrail,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        # scan_custom_insight_lambda = tasks.LambdaInvoke(self, id="scan_custom_insight",
        #     lambda_function=scan_custom_insight,
        #     # Lambda's result is in the attribute `Payload`
        #     payload=sfn.TaskInput.from_json_path_at("$.Payload")
        # )  
        scan_guardduty_lambda = tasks.LambdaInvoke(self, id="scan_guardduty",
            lambda_function=scan_guardduty,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        
        parallel = sfn.Map(self, "ScanServicesToRunMap",
                                               max_concurrency=1,
                                               ).iterator(scan_config_lambda.next (scan_iam_role_lambda).next(scan_cloudtrail_lambda).next(scan_guardduty_lambda).next(scan_securityhub_lambda)) 
        definition= parallel
        scan_state_machine=sfn.StateMachine(self, "StateMachine",
            state_machine_name="testing",
            state_machine_type=sfn.StateMachineType.STANDARD,
            definition=definition,
            timeout=Duration.minutes(5),
            tracing_enabled=True
        )                                                                                                                                     
        account_table = _dynamodb.Table(self, "AccountTable",table_name="TlsAutomationStack",
                                        partition_key=_dynamodb.Attribute(name="region",
                                                                          type=_dynamodb.AttributeType.STRING),
                                        sort_key=_dynamodb.Attribute(name="service",
                                                                     type=_dynamodb.AttributeType.STRING),                                                                                                                                                         
                                        billing_mode=_dynamodb.BillingMode.PAY_PER_REQUEST,
                                        removal_policy=RemovalPolicy.DESTROY)


        api = apigateway.LambdaRestApi(self, "Scan_State_Machine_API",
            rest_api_name="KB_Scan_State_Machine_API",
            deploy=True,
            handler=start_scan_stepfunction
        )


        # SNS Implementation

        scan_failure_notification_topic = _sns.Topic(self, "SendFailureSNSNotificationTopic",
                                                     topic_name="KB_Send_Failure_Notification_Topic")

        # email_address = "ndrenm@amazon.com"
        email_address = "amutexkb8@gmail.com"
        scan_failure_notification_topic.add_subscription(_sns_subscriptions.EmailSubscription(email_address))

        new_account_queue = _sqs.Queue(self, "NewAccountQueue",
                                       queue_name="KB_New_Account_Queue",
                                       visibility_timeout=Duration.seconds(900))

        update_account_event_rule=_cloudtrail.Trail.on_event(self,"updateaccountcloudtrailevent",
        target=_targets.LambdaFunction(event_lambda))
                                                   
        new_account_event_rule = _cloudtrail.Trail.on_event(self, "NewAccountCloudTrailEvent",
                                                            target=_targets.SqsQueue(new_account_queue))

        details = {
            "eventSource": ["lambda.amazonaws.com"],
            "eventName": ["UpdateFunctionCode20150331v2"],     
             "requestParameters": {
                    "functionName": ["arn:aws:lambda:us-east-1:109661032234:function:KB-*"]
         }
         }
        update_account_event_rule.add_event_pattern(
            account=["109661032234"],
            detail=details  )
            
        detail = {
            "eventName": ["DescribeSecret"],
            "requestParameters": {
                "secretId": ["do_not_touche"]

            }
        }
        new_account_event_rule.add_event_pattern(
            account=["109661032234"],
            detail=detail
        )
        call_lambda_sqs_event_source = SqsEventSource.SqsEventSource(new_account_queue)

        call_update_lambda.add_event_source(call_lambda_sqs_event_source)   
# move account
        move_account_queue = _sqs.Queue(self, "moveAccountQueue",
                                       queue_name="KB_move_Account_Queue",
                                       visibility_timeout=Duration.seconds(60))


                                                   
        move_account_event_rule = _cloudtrail.Trail.on_event(self, "moveAccountCloudTrailEvent",
                                                            target=_targets.SqsQueue(move_account_queue))

        detail = {
            "eventName": ["MoveAccount"],
            "requestParameters": {
                "accountId": ["449081201015"],
                "destinationParentId": ['ou-bish-7neva622']
            }
        }

        move_account_event_rule.add_event_pattern(
            account=["109661032234"],
            source=["aws.organizations"],
            detail=detail
        )

        move_lambda_sqs_event_source = SqsEventSource.SqsEventSource(move_account_queue)

        start_scan_stepfunction.add_event_source(move_lambda_sqs_event_source) 
                                        
                        

               
        
    
