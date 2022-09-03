# Modify CloudTrail Microservice

The Modify CloudTrail Microservice is used to create a CloudTrail instance for a given account.  This is create if the account does not have any existing CloudTrail setup or if the account does not have a CloudTrail that uses the KB Logging bucket. The microservice constructs a list showing each CloudTrail that the account has. It also checks to see if there is a CloudTrail that points to the KB CloudTrail bucket.  If the account has a CloudTrail that uses the KB Logging bucket, no remediation will be required for the account.  In the event that the account does not CloudTrail enabled or does not have Cloudtrail using the KB CloudTrail bucket, a new CloudTrail instance will be created.

This microservice is an AWS Lambda function using a Python 3.9 runtime.

## Components

1. handler - this is the main entry point of the Lambda function and takes an event as a parameter.
2. create_cloudtrail - Takes client, CloudTrail name, CloudTrail bucket name, CloudTrail S3 Key Prefix as parameters. Using the client that is passed in, the function creates a CloudTrail instance using the name, bucket name, and S3 Key Prefix parameters.  If successful, it returns the TrailName and TrailARN that was setup.  If there is an error, it returns the error message.
3. create_cloudtrail_event_selectors - Takes client, CloudTrail name as parameters.  Using the client that is passed in, the function creates event selectors for the given CloudTrail name parameter.  If successful, it returns the response showing that the event selector was setup for the CloudTrail name.  If there is an error, it returns the error message.

## Parameters

- accountData: object
  - accountId: string
- scanData: object
  - cloudTrailList: list
    - name: string
    - s3BucketName: string
    - isMultiRegionTrail: boolean
    - homeRegion: string
    - isOrganizationTrail: boolean
  - status: string

## Response
Code 200: successful operation
```
{
  "accountData": {
    "accountId": "string"
  },
  "implementationData": {
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

This microservice runs as part of KB Implementation State Machine Step Functions process.
