# Delete AWS Custom insight Microservice

The Delete AWS Custom insight Microservice is used to delete a given custom insight based on the account's AWS Custom insight scanning results.

This microservice is an AWS Lambda function using a Python 3.9 runtime.

## Components

1. handler - this is the main entry point of the Lambda function and takes an event as a parameter.

## Parameters

- accountData: object
  - accountId: string
- deleteData: object
  - stackName: string


## Response

Code 200: successful operation
```
{
  "accountData": {
    "accountId": "string"
  },
  "deleteData": {
    "service": "string",
    "stackName": "string",
    "status": "string"
  }
}
```

## How to start

This microservice is ran as needed and is not part of the scanning or implementation processes.
