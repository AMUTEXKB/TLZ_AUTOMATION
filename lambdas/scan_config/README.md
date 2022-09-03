# Scan AWS Config Microservice

The Scan AWS Config Microservice is used to look at an account's AWS Config enabled. The microservice constructs shows if AWS Config is enabled in the target account in us-east-1. If AWS Config is already enabled in the account, the response will be set to 'enabled, In the event that the account does not have AWS Config enabled , the status in the response will be set to 'disabled' and remediation will be required.

This microservice is an AWS Lambda function using a Python 3.9 runtime.

## Components

1. handler - this is the main entry point of the Lambda function and takes an event as a parameter.


## Parameters

- accountData: object
  - accountId: string

## Response
Code 200: successful operation
```
{
  "input": [

    {
      "enabled_services": [
        "string"
      ],
      "account_data": {
        "accountId": "string",
        "destinationParentId": "string",
        "sourceParentId": "string"
      },
      "scan_data": {
        "service": "string",
        "status": "string"
      }
    },


This microservice runs as part of KB Scan State Machine Step Functions process.
