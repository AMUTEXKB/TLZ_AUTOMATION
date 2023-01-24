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
)
from constructs import Construct

class TlsAutomationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here

        # example resource
        # queue = sqs.Queue(
        #     self, "TlsAutomationQueue",
        #     visibility_timeout=Duration.seconds(300),
        # )

        #s3bucket
        bucket=_s3.Bucket(self, id="Bucket",
                bucket_name="amudarole",
                removal_policy=RemovalPolicy.DESTROY
            )
        s3deploy.BucketDeployment(self, id="DeployWebsite",
            sources=[s3deploy.Source.asset("./lambdas/bucket_deployment")],
            destination_bucket=bucket
        )    
        # Lambda Role Definitions
        security_scan_lambda_role = _iam.Role.from_role_arn(self, "SecurityScanLambdaRole",
                                                            "arn:aws:iam::672432851135:role/KB_assumed_role",

                                                            mutable=False)

        implementation_lambda_role = _iam.Role(self, "ImplementationLambdaRole",
                                               assumed_by=_iam.ServicePrincipal("lambda.amazonaws.com"),
                                               role_name="KB_Implementation_Role")

        implementation_lambda_role.add_to_policy(_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            actions=[
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "xray:GetSamplingRules",
                "xray:GetSamplingTargets",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "states:*",
                "dynamodb:*",
                "ssm:GetParameter",
                "ssm:PutParameter",
                "s3:*",
                "sns:*",
                "lambda:*",
                "states:SendTaskSuccess",
                "states:SendTaskFailure"
            ],
            resources=[
                "*",
            ],
        ))  
        # scan Lambda Handlers Definitions
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
        scan_guardduty= _lambda.Function(self, "guarddurtScanLambdaFunction",
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
        scan_custom_insight= _lambda.Function(self, "custominsightScanLambdaFunction",
                                                       function_name="KB_scan_Custom_Insight",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/scan_custom_insight"),
                                                       timeout=Duration.seconds(10),
                                                       environment={
                                                            "insight_name":"CIRRUSSCAN_INSIGHT_NAME",
                                                            "aws_service":"custom_insight", 
                                                            "modify_service":'securityhub',
                                                            "aws_service":"custom insight", 
                                                            "target_region":"us-east-1",
                                                            "tablename":"TlsAutomationStack"
                                                       },
                                                       role=security_scan_lambda_role)
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
        start_scan_stepfunction= _lambda.Function(self, "StartScanStepFunction",
                                                       function_name="KB_start_scanstepfunction",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/start_stepfunction"),
                                                       timeout=Duration.seconds(10),
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
        scan_custom_insight_lambda = tasks.LambdaInvoke(self, id="scan_custom_insight",
            lambda_function=scan_custom_insight,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )  
        scan_guardduty_lambda = tasks.LambdaInvoke(self, id="scan_guardduty",
            lambda_function=scan_guardduty,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        # SQS implementation

        implementation_queue =_sqs.Queue(self, "ImplementationQueue",
                                                             queue_name="implementation_queue"
                                                             ) 
        implementation_queue_start_lambda= tasks.SqsSendMessage(self, "Send1",
                                                                      queue=implementation_queue,
                                                                      message_body=sfn.TaskInput.from_json_path_at("$"))
 
        parallel = sfn.Map(self, "ScanServicesToRunMap",
                                               max_concurrency=1,
                                               ).iterator(scan_config_lambda.next (scan_iam_role_lambda).next(scan_cloudtrail_lambda).next(scan_guardduty_lambda).next(scan_securityhub_lambda))
        definition=sfn.Parallel(self,"parrallel")
        definitions=definition.branch(parallel.next(implementation_queue_start_lambda)) 
        scan_state_machine=sfn.StateMachine(self, "StateMachine",
            state_machine_name="KB_scan_state_machine",
            state_machine_type=sfn.StateMachineType.STANDARD,
            definition=definitions,
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
        api.root.add_method("GET")
        # SNS Implementation

        scan_failure_notification_topic = _sns.Topic(self, "SendFailureSNSNotificationTopic",
                                                     topic_name="KB_Send_Failure_Notification_Topic")

        # email_address = "ndrenm@amazon.com"
        email_address = "amutexkb8@gmail.com"
        scan_failure_notification_topic.add_subscription(_sns_subscriptions.EmailSubscription(email_address))
        


        # implementation Lambda Handlers Definitions 
        implementation_lambda=_lambda.Function(self, "implementation_lambda",
                                                        function_name="KB_implementation_lambda",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/implementation_lambda"),
                                                        timeout=Duration.seconds(10),
                                                        environment={
                                                            "implementation_state_machine":"KB_implementation_state_machine",
                                                            "target_region":"us_east_1"},
                                                        role=security_scan_lambda_role)

        modify_custom_insight= _lambda.Function(self, "custominsightImplementationLambdaFunction",
                                                        function_name="KB_modify_Custom_Insight",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/modify_custom_insight"),
                                                        timeout=Duration.seconds(10),
                                                        environment={
                                                            "target_region":"us-east-1",
                                                            "insight_name":"KB",
                                                            "aws_service":"custom insight", 
                                                            "modify_service":'securityhub',
                                                            "dynamodbtable_name":"TlsAutomationStack"},
                                                        role=security_scan_lambda_role)

        modify_waf= _lambda.Function(self, "wafImplementationLambdaFunction",
                                                        function_name="KB_modify_waf",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/waf_modify"),
                                                        timeout=Duration.seconds(10),
                                                        environment={
                                                            "target_region" :"us-east-1",
                                                            "stack_name" :"wafrole", 
                                                            "bucket_name" : "amudarole",
                                                            "deploy_version": "1",
                                                            "godaddy_web_acl_v2":"GoDaddyDefaultWebACLv2",
                                                            "aws_service":"waf", 
                                                            "modify_service":'cloudformation',
                                                            "dynamodbtable_name":"TlsAutomationStack"},
                                                        role=security_scan_lambda_role)                                                                                                                 

        modify_config= _lambda.Function(self, "configImplementationLambdaFunction",
                                                       function_name="KB_modify_Config",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_config"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                           "aws_service" : "config",
                                                            "config_name" :"default",
                                                            "dynamodbtable_name":"TlsAutomationStack",
                                                            "target_region" :"us-east-1"},
                                                       role=security_scan_lambda_role)
        modify_iam_role= _lambda.Function(self, "IamRoleImplementationLambdaFunction",
                                                       function_name="KB_modify_IAM_role",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_IAM_role"),
                                                       timeout=Duration.seconds(300),
                                                        environment={
                                                                "aws_service":"iam",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack",
                                                                "bucket_name":"amudarole",
                                                                "stack_name":"role",
                                                                "deploy_version":"1",
                                                                "audit_account_param_buckets":"arn:aws:s3:::amudakb",
                                                                "audit_account_result_buckets":"arn:aws:s3:::amudakb"
                                                        },                                                       
                                                       role=security_scan_lambda_role)
        modify_guardduty= _lambda.Function(self, "GuarddutyImplementationLambdaFunction",
                                                       function_name="KB_modify_Guardduty",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_guardduty"),
                                                       timeout=Duration.seconds(10),
                                                        environment={
                                                                "aws_service":"guardduty",
                                                                "target_region":"us-east-1",
                                                                "tablename":"TlsAutomationStack",
                                                                "guardduty_logging_bucket_name":"amudakb"
                                                        },
                                                       role=security_scan_lambda_role)    
        modify_securityhub= _lambda.Function(self, "securityhubImplementationLambdaFunction",
                                                       function_name="KB_modify_securityhub",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_securityhub"),
                                                       timeout=Duration.seconds(10),
                                                       role=security_scan_lambda_role)                                                                                                           

    # implementation Step functions Definition
        modify_config_lambda= tasks.LambdaInvoke(self, id="modify_config_lambda",
            lambda_function=modify_config,
            # Lambda's result is in the attribute `Payload`
            
        )
        modify_iam_role_lambda = tasks.LambdaInvoke(self, id="modify_iam_role",
            lambda_function=modify_iam_role,
            # Lambda's result is in the attribute `Payload`
           payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        modify_custom_insight_lambda = tasks.LambdaInvoke(self, id="modify_custom_insight",
            lambda_function=modify_custom_insight,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
            
        )  
        modify_guardduty_lambda = tasks.LambdaInvoke(self, id="modify_guardduty",
            lambda_function=modify_guardduty,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
            
        ) 
        modify_securityhub_lambda = tasks.LambdaInvoke(self, id="modify_securityhub",
            lambda_function=modify_securityhub,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
            
        ) 
        map= sfn.Map(self, "implementationServicesToRunMap",
                                               max_concurrency=1,
                                               ).iterator(modify_config_lambda.next(modify_securityhub_lambda).next(modify_custom_insight_lambda).next(modify_guardduty_lambda))
        definition=sfn.Parallel(self,"parrallels")
        definitionss=definition.branch(map.next(modify_iam_role_lambda))         
        implementation_state_machine=sfn.StateMachine(self,id="implementationStateMachine",
            state_machine_name="KB_implementation_state_machine",
            definition=definitionss,
            timeout=Duration.minutes(6),
            tracing_enabled=True
        )                                                                                                                                                                              
        # # Set Implementation Lambda event
        implementation_start_lambda_sqs_event_source =SqsEventSource.SqsEventSource(queue=implementation_queue,
                                                                                        batch_size=1)
        implementation_lambda.add_event_source(implementation_start_lambda_sqs_event_source)

        delete_custom_insight= _lambda.Function(self, "custominsightdeleteLambdaFunction",
                                                        function_name="KB_delete_Custom_Insight",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/delete_custom_insight"),
                                                        timeout=Duration.seconds(10),
                                                        role=security_scan_lambda_role) 
        delete_guardduty= _lambda.Function(self, "guarddutydeleteLambdaFunction",
                                                        function_name="KB_delete_guardduty",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/delete_guardduty"),
                                                        timeout=Duration.seconds(10),
                                                        environment={
                                                            "target_region":"us-east-1"
                                                        },
                                                        role=security_scan_lambda_role) 
        delete_waf= _lambda.Function(self, "wafdeleteLambdaFunction",
                                                        function_name="KB_delete_waf",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/delete_waf"),
                                                        timeout=Duration.seconds(10),
                                                        environment={
                                                            "target_region":"us-east-1",
                                                            "stack_name":"wafrole"
                                                        },
                                                        role=security_scan_lambda_role)    
        delete_IAM_role= _lambda.Function(self, "iamroledeleteLambdaFunction",
                                                        function_name="KB_delete_iam_role",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/delete_IAM_role"),
                                                        timeout=Duration.seconds(10),
                                                        role=security_scan_lambda_role)                                                                                                                                                                            
        delete_config= _lambda.Function(self, "configdeleteLambdaFunction",
                                                        function_name="KB_delete_config",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/delete_config"),
                                                        timeout=Duration.seconds(10),
                                                        role=security_scan_lambda_role)
    # delete Step functions Definition
        delete_config_lambda= tasks.LambdaInvoke(self, id="delete_config_lambda",
            lambda_function=delete_config,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_object({})
        
        )
        delete_iam_role_lambda = tasks.LambdaInvoke(self, id="delete_iam_role",
            lambda_function=delete_IAM_role,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
        )
        delete_custom_insight_lambda = tasks.LambdaInvoke(self, id="delete_custom_insight",
            lambda_function=delete_custom_insight,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
            
        )  
        delete_guardduty_lambda = tasks.LambdaInvoke(self, id="delete_guardduty",
            lambda_function=modify_guardduty,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_json_path_at("$.Payload")
            
        ) 
        parallelss= sfn.Parallel(self,id= "deleteParallels")   
        definitionss= parallelss.branch(delete_config_lambda.next(delete_iam_role_lambda).next(delete_custom_insight_lambda).next(delete_guardduty_lambda))
        delete_state_machine=sfn.StateMachine(self,id="deleteStateMachine",
            state_machine_name="KB_delete_state_machine",
            definition=definitionss,
            timeout=Duration.minutes(6),
            tracing_enabled=True
        ) 

        # #org account 
                                                                                                                                                                  
        # # SQS implementation

        new_account_queue = _sqs.Queue(self, "NewAccountQueue",
                                       queue_name="KB_New_Account_Queue")

        new_account_event_rule = _cloudtrail.Trail.on_event(self, "NewAccountCloudTrailEvent",
                                                            target=_targets.SqsQueue(new_account_queue))

        detail = {
            "eventName": ["MoveAccount"],
            "requestParameters": {
                "destinationParentId": ["ou-bish-j7mfxuat"]
            }
        }

        new_account_event_rule.add_event_pattern(
            account=["449081201015"] ,
            source=["aws.organizations"],
            detail=detail
        )


        call_scan_lambda_role = _iam.Role(self, "CallScanLambdaRole",
                                          assumed_by=_iam.ServicePrincipal("lambda.amazonaws.com"),
                                          role_name="KB_Call_Scan_Role")

        call_scan_lambda_role.add_to_policy(_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            actions=[
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "xray:GetSamplingRules",
                "xray:GetSamplingTargets",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "apigateway:*"
            ],
            resources=[
                "*",
            ],
        ))

        # call_scan_lambda = _lambda.Function(self, "CallScanAPILambdaFunction",
        #                                     function_name="KB_Call_Scan_API",
        #                                     handler="lambda_function.lambda_handler",
        #                                     runtime=_lambda.Runtime.PYTHON_3_9,
        #                                     code=_lambda.Code.from_asset("lambdas/automation_org"),
        #                                     timeout=Duration.seconds(10),
        #                                     role=call_scan_lambda_role)
                        

        # call_lambda_sqs_event_source = SqsEventSource.SqsEventSource(new_account_queue)

        # call_scan_lambda.add_event_source(call_lambda_sqs_event_source)                                                                                                                                                                     