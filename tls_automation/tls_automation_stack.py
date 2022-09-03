from ast import Expression
import fnmatch
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
                                                     

    # Scan Step functions Definition
        scan_config_lambda= tasks.LambdaInvoke(self, id="scan_config_lambda",
            lambda_function=scan_config,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_object({})
        )
        scan_iam_role_lambda = tasks.LambdaInvoke(self, id="scan_iam_role",
            lambda_function=scan_iam_role,
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
        # SQS implementation

        implementation_queue =_sqs.Queue(self, "ImplementationQueue",
                                                             queue_name="implementation_queue"
                                                             ) 
        implementation_queue_start_lambda= tasks.SqsSendMessage(self, "Send1",
                                                                      queue=implementation_queue,
                                                                      message_body=sfn.TaskInput.from_json_path_at("$"))

        parallel = sfn.Parallel(self, "Parallel")   
        definition= parallel.branch(scan_config_lambda.next (scan_iam_role_lambda).next(scan_cloudtrail_lambda).next(scan_custom_insight_lambda).next(implementation_queue_start_lambda))
        scan_state_machine=sfn.StateMachine(self, "StateMachine",
            state_machine_name="KB_scan_state_machine",
            state_machine_type=sfn.StateMachineType.EXPRESS,
            definition=definition,
            timeout=Duration.minutes(5),
            tracing_enabled=True
        )        
        account_table = _dynamodb.Table(self, "AccountTable",table_name="TlsAutomationStack",
                                        partition_key=_dynamodb.Attribute(name="service", type=_dynamodb.AttributeType.STRING),                                                                                                                                                         
                                        billing_mode=_dynamodb.BillingMode.PAY_PER_REQUEST,
                                        removal_policy=RemovalPolicy.DESTROY)


        api = apigateway.RestApi(self, "Scan_State_Machine_API",
            rest_api_name="KB_Scan_State_Machine_API",
            deploy=True
        )
        api.root.add_method("GET", apigateway.StepFunctionsIntegration.start_execution(scan_state_machine))
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
                                                        role=security_scan_lambda_role)

        modify_custom_insight= _lambda.Function(self, "custominsightImplementationLambdaFunction",
                                                        function_name="KB_modify_Custom_Insight",
                                                        handler="lambda_function.lambda_handler",
                                                        runtime=_lambda.Runtime.PYTHON_3_9,
                                                        code=_lambda.Code.from_asset(
                                                            "lambdas/modify_custom_insight"),
                                                        timeout=Duration.seconds(10),
                                                        role=security_scan_lambda_role)

        modify_config= _lambda.Function(self, "configImplementationLambdaFunction",
                                                       function_name="KB_modify_Config",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_config"),
                                                       timeout=Duration.seconds(10),
                                                       role=security_scan_lambda_role)
        modify_iam_role= _lambda.Function(self, "IamRoleImplementationLambdaFunction",
                                                       function_name="KB_modify_IAM_role",
                                                       handler="lambda_function.lambda_handler",
                                                       runtime=_lambda.Runtime.PYTHON_3_9,
                                                       code=_lambda.Code.from_asset(
                                                           "lambdas/modify_IAM_role"),
                                                       timeout=Duration.seconds(300),
                                                       role=security_scan_lambda_role)

    # implementation Step functions Definition
        modify_config_lambda= tasks.LambdaInvoke(self, id="modify_config_lambda",
            lambda_function=modify_config,
            # Lambda's result is in the attribute `Payload`
            payload=sfn.TaskInput.from_object({})
        
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
        parallels = sfn.Parallel(self,id= "Parallels")   
        definitions= parallels.branch(modify_config_lambda.next(modify_iam_role_lambda).next(modify_custom_insight_lambda))
        implementation_state_machine=sfn.StateMachine(self,id="implementationStateMachine",
            state_machine_name="KB_implementation_state_machine",
            definition=definitions,
            timeout=Duration.minutes(6),
            tracing_enabled=True
        )                                                                                                                                                                              
        # # Set Implementation Lambda event
        implementation_start_lambda_sqs_event_source =SqsEventSource.SqsEventSource(queue=implementation_queue,
                                                                                        batch_size=1)
        implementation_lambda.add_event_source(implementation_start_lambda_sqs_event_source)
                                                                                                           
                                                                                                                                                                     

 