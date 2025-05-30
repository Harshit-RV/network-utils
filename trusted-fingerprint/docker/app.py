import paramiko
import socket
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class RequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        event_body = json.loads(post_data)

        if 'Authorization' not in event_body:
            self._set_headers(403)
            self.wfile.write(json.dumps({'body': 'Forbidden'}).encode())
            return

        auth = event_body['Authorization'].split()
        host = event_body['Host']
        key_type = event_body['KeyType']

        secret_token = os.environ['SECRET_TOKEN']
        try:
            keyscan_timeout = os.environ['KEYSCAN_TIMEOUT']
        except:
            keyscan_timeout = 60

        if len(auth) != 2 or auth[0] != "Bearer" or auth[1] != secret_token:
            self._set_headers(403)
            self.wfile.write(json.dumps({'body': 'Forbidden'}).encode())
            return

        try:
            sock = socket.create_connection((host, 22), timeout=keyscan_timeout)
            transport = paramiko.Transport(sock)
            transport.get_security_options().key_types = [key_type]
            transport.start_client()

            key = transport.get_remote_server_key()
            key_body = key.get_base64()

            transport.close()

            self._set_headers(200)
            self.wfile.write(key_body.encode())
        except:
            self._set_headers(500)
            self.wfile.write(json.dumps({'body': 'Internal Server Error'}).encode())
        finally:
            sock.close()


def run(server_class=HTTPServer, handler_class=RequestHandler):
    port = int(os.environ.get('TRUSTED_FINGERPRINT_PORT', 80))
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}')
    httpd.serve_forever()


if __name__ == "__main__":
    run()
