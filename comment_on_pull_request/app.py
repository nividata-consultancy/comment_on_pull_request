import os
import json
from datetime import datetime, timedelta
import time

import base64
import boto3
from botocore.exceptions import ClientError
import requests


cloudwatch_client = boto3.client('logs')


def lambda_handler(event, context):
    """Lambda function to process cloudwatch logs and auto comment on pull request
    
        Parameters
        ----------
        event: dict, required
            API Gateway Lambda Proxy Input Format

        context: object, required
            Lambda Context runtime methods and attributes
    """
    pr_handler = PullRequestHandler()
    # Execute the comment URL
    comment_url = pr_handler.extract_comment_url(event)
    pr_handler.comment_on_pull_request(comment_url)
    return {"status": 200, "message": "Comment sent successfully"}


class PullRequestHandler:
    CLOUDWATCH_QUERY = "fields @message"
    CLOUDWATCH_LOG_GROUP = '/aws/lambda/comment_on_pull_request'
    SECRET_NAME = "github-authtoken"
    REGION = "ap-south-1"

    def __init__(self):
        self.AUTH_TOKEN = self.get_secret('GITHUB_AUTH_TOKEN')

    def comment_on_pull_request(self, url):
        # Fetch logs from the S3
        single_log = self.get_logs_from_cloudwatch()
        # POST request on comment url
        self.execute_url(url, single_log)

    @staticmethod
    def extract_comment_url(event):
        body = json.loads(event["body"])
        return body["pull_request"]["comments_url"]

    def execute_url(self, url, comment_data):
        json_data = json.dumps({"body": f"Comment from Cloudwatch: {comment_data}"})
        requests.post(url, data=json_data, headers=self.get_headers())

    def get_headers(self):
        return {"Authorization": f"token {self.AUTH_TOKEN}"}

    def get_logs_from_cloudwatch(self):
        query = self.CLOUDWATCH_QUERY
        log_group = self.CLOUDWATCH_LOG_GROUP
        
        start_query_response = cloudwatch_client.start_query(
            logGroupName=log_group,
            startTime=int((datetime.today() - timedelta(hours=24)).timestamp()),
            endTime=int(datetime.now().timestamp()),
            queryString=query,
        )

        query_id = start_query_response['queryId']
        response = None
        while not response:
            time.sleep(1)
            response = cloudwatch_client.get_query_results(
                queryId=query_id
            )

        result = ""
        for i in range(20):
            try:
                log = response['results'][i]
                result += log[0]['value']
            except IndexError:
                pass
        return result if result else "No data available"

    def get_secret(self, env_name):
        secret_name = self.SECRET_NAME
        region_name = self.REGION

        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
        else:
            # Decrypts secret using the associated KMS CMK.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
            else:
                decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

        return json.loads(get_secret_value_response['SecretString'])[env_name]
