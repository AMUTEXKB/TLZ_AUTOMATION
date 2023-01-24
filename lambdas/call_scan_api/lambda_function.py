import boto3
import botocore
import requests
import json

client = boto3.client('apigateway')
def lambda_handler(event, context):
    try:
        response = client.get_rest_apis(
    )
        if len(response["items"]) > 0:
            for items in response['items']:
                if  items['name'] == "dean":
                    api_id= items["id"]

                    params = {"input": "START",
                            "stateMachineArn": "arn:aws:states:us-east-1:672432851135:stateMachine:KB_Scan_StateMachine"}
                    print(f"params: {params}")
                    response = requests.get(f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/", json=params)
                    print(response)
                    return "Success"

    except botocore.exceptions.ClientError as error:
        print(error)
        return "Failed"