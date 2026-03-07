FROM alpine:latest
RUN apk add --update python3 py3-pip
WORKDIR /password-manager/
COPY . ./
RUN touch /password-manager/password_manager.db
RUN touch /password-manager/default_credentials.txt
RUN pip install -r requirements.txt --break-system-packages
EXPOSE 443/tcp
CMD python3 server.py