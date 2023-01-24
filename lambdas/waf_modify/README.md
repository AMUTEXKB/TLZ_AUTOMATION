# Defining parameters for target region 

Use the CfnParameter class to define a parameter. You'll want to specify at least a type,default value and a description for most parameters, though both are technically optional. The description  appears when the user is prompted to enter the parameter's value in the AWS CloudFormation console. 

<!-- Note
You can define parameters in any scope, but we recommend defining parameters at the stack level so that their logical ID does not change when you refactor your code. -->

This AWS CDK is using a Python programming language
# Syntax
        upload_region_name = CfnParameter(self, "uploadRegionName", type="String",
            default="us-west-2",
            description="The name of the Amazon Target Region  where AWS Lambda would Scan and Implement Services.")  

# Using parameters      

A CfnParameter instance exposes its value to your AWS CDK app via a token. Like all tokens, the parameter's token is resolved at synthesis time, but it resolves to a reference to the parameter defined in the AWS CloudFormation template, which will be resolved at deploy time, rather than to a concrete value.

 Property --->	kind of value

value_as_string	--> The token represented as a string 

# syntax
    environment={"target_region":upload_region_name.value_as_string }

# Deploying with parameters

A generated template containing parameters can be deployed in the usual way through the AWS CloudFormation console; you are prompted for the values of each parameter.

The AWS CDK Toolkit (cdk command-line tool) also supports specifying parameters at deployment. You may provide these on the command line following the --parameters flag. You might deploy a stack that uses the uploadRegionName parameter like this.

# syntax

    cdk deploy AwsEventbridgeListenerStack --parameters uploadRegionName= us-west-2

<!-- In a situation where a defualt parameter value is specified ,there is no need to specify the same parameter during cdk deploy-->

    cdk deploy AwsEventbridgeListenerStack 

By default, the AWS CDK retains values of parameters from previous deployments and uses them in subsequent deployments if they are not specified explicitly. Use the --no-previous-parameters flag to require all parameters to be specified.