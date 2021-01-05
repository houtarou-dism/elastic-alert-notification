import os
import ast
import json
import boto3
import requests
from dotenv import load_dotenv


def lambda_handler(event, context):

    load_dotenv()

    slack_webhook_url = os.environ['SLACK_URL']

    response = boto3.client('lambda').invoke(
        FunctionName=os.environ['FUNCTION_NAME'],
        InvocationType='RequestResponse',
        Payload='{}',
    )

    response_payload = ast.literal_eval(
        response["Payload"].read().decode('utf-8'))

    payload = {
        "attachments": [
            {
                "fallback": response_payload["fallback"],
                "pretext": json.dumps(response_payload["body"],
                                      indent=4, ensure_ascii=False)
            }
        ]
    }

    requests.post(slack_webhook_url, data=json.dumps(payload))


if __name__ == "__main__":
    lambda_handler({}, {})
