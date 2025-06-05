FROM alpine:3.18.3

RUN apk add bash curl unzip groff jq python3 openssh openssl

WORKDIR /app

COPY generate-certificate-curl.sh .
COPY aws-auth-header.py .

RUN chmod +x generate-certificate-curl.sh

ENTRYPOINT ["bash", "generate-certificate-curl.sh"]