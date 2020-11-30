This is a sample single web-page application example with AWS CloudFront, Cognito User Pool for authentication and Cognito Identity Pool for authorization for AWS resources usage.

Partiall it's snatched from the AWS blog post:
https://aws.amazon.com/blogs/security/how-to-add-authentication-single-page-web-application-with-amazon-cognito-oauth2-implementation/

And this gist for cloudformation details: https://gist.github.com/singledigit/2c4d7232fa96d9e98a3de89cf6ebe7a5

1. Deploy the stack
`
serverless deploy --authName=testPool --googleClientId=YOUR_CLIENT --googleClientSecret=G_CLIENT_SECRET
`

2. Sync application code to S3
`
aws s3 sync app s3://test-single-page-app
`

TODO:

- add cognito-identity-js lib usage as example