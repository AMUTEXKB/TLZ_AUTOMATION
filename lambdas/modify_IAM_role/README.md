# Modify AWS IAM Advanced Microservice

The Modify AWS IAM  Microservice is used to enable AWS IAM role in the target account based on the scanning results.

This microservice is an AWS Lambda function using a Python 3.9 runtime.


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
    {
        "accountData": {
            "accountId": "string"
      },
        "implementation_data": {
                "service": "string",
                "status": "string",
        }
    },
