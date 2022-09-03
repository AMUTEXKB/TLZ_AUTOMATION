# Scan CloudTrail Microservice

The Scan CloudTrail Microservice is used to look at an account's CloudTrail and see if they are enabled and if they have a CloudTrail that uses the KB CloudTrail bucket. The microservice constructs a list showing each CloudTrail that the account has. It also checks to see if there is a CloudTrail that points to the KB CloudTrail bucket.  If the account has a CloudTrail that uses the KB CloudTrail bucket, the status in the response will be set to 'enabled' and no CloudTrail remediation will be required for the account.  In the event that the account does not CloudTrail enabled or does not have Cloudtrail using the KB CloudTrail bucket, the status in the response will be set to 'disabled' and remediation will be required.

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
  "accountData": {
    "accountId": "string"
  },
  "scanData": {
    "service": "string",
    "cloudTrailList": [
      {
        "name": "string",
        "s3BucketName": string,
        "isMultiRegionTrail": boolean,
        "homeRegion": string,
        "isOrganizationTrail": boolean
      }
    ],
    "status": "string"
  }
}
```

## How to start

This microservice runs as part of KB Scan State Machine Step Functions process.
