# Delete Config Microservice

The Delete Config Microservice is used to delete a given Config based on the account's Config scanning results.

This microservice is an AWS Lambda function using a Python 3.9 runtime.

## Components

1. handler - this is the main entry point of the Lambda function and takes an event as a parameter.

## Parameters

- accountData: object
  - accountId: string
- deleteData: object
  - configName: string


## Response

Code 200: successful operation
```
{
  "accountData": {
    "accountId": "string"
  },
  "deleteData": {
    "service": "string",
    "configName": "string",
    "status": "string"
  }
}
```

## How to start

This microservice is ran as needed and is not part of the scanning or implementation processes.
