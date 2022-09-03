# Modify AWS Custom insight Advanced Microservice

The Modify AWS Custom insight Microservice is used to  Creates a custom security hub insight to display active high severity kbscan findings in the target account based on the scanning results.

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
