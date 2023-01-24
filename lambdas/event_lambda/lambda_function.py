import json
import boto3
import logging


def lambda_handler(event, context):
    client = boto3.client('lambda')
    functionname= event["detail"]["requestParameters"]["functionName"]
    response = client.invoke(
        FunctionName=functionname,
        InvocationType='Event',
        ClientContext='string',
        Payload=b'',

    )
    print(response)
    print(functionname)