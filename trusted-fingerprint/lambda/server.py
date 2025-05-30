import paramiko
import json
import os
import socket


def lambda_handler(event, context):
    try:
        event_body = json.loads(event['body'])

        if 'Authorization' not in event_body:
            return {
                'statusCode': 403,
                'body': 'Forbidden'
            }

        auth = event_body['Authorization'].split()
        host = event_body['Host']
        key_type = event_body['KeyType']

        secret_token = os.environ['SECRET_TOKEN']
        try:
            keyscan_timeout = os.environ['KEYSCAN_TIMEOUT']
        except:
            keyscan_timeout = 60

        if len(auth) != 2 or auth[0] != "Bearer" or auth[1] != secret_token:
            return {
                'statusCode': 403,
                'body': 'Forbidden'
            }

        sock = socket.create_connection((host, 22), timeout=keyscan_timeout)
        transport = paramiko.Transport(sock)
        transport.get_security_options().key_types = [key_type]
        transport.start_client()

        key = transport.get_remote_server_key()
        key_body = key.get_base64()

        transport.close()

        return {
            'statusCode': 200,
            'body': key_body
        }
    except:
        return {
            'statusCode': 500,
            'body': 'Internal Server Error '
        }
    finally:
        sock.close()
