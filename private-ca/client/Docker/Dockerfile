FROM alpine:3.18.3

RUN apk add bash curl unzip groff jq python3 openssh openssl
RUN python3 -m ensurepip
RUN pip3 install boto3

WORKDIR /app
COPY generate-certificate-curl.sh /app
COPY run.sh /app
COPY aws-auth-header.py /app

RUN chmod +x generate-certificate-curl.sh 
RUN chmod +x run.sh

ENTRYPOINT ["/app/run.sh" ]
