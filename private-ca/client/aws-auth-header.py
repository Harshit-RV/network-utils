import sys
from datetime import datetime
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

if __name__ == "__main__":
    access_key_id = sys.argv[1]
    secret_access_key = sys.argv[2]
    session_token = sys.argv[3]
    aws_region = sys.argv[4]

    sts_host = "sts." + aws_region + ".amazonaws.com"
    request_parameters = 'Action=GetCallerIdentity&Version=2011-06-15'
    request_headers = {
        'Host': sts_host,
        'X-Amz-Date': datetime.now().strftime('%Y%m%dT%H%M%SZ'),
        'Aud': 'FundwaveCA'
    }
    request = AWSRequest(method="POST", url="/", data=request_parameters, headers=request_headers)
    boto_creds = Credentials(access_key_id, secret_access_key,token=session_token)
    auth = SigV4Auth(boto_creds, "sts", aws_region)
    auth.add_auth(request)

    authorization = request.headers["Authorization"]
    date = request.headers["X-Amz-Date"]

    response = f'{{"Authorization": "{authorization}", "Date": "{date}"}}'
    print(response)