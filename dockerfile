FROM ubuntu:latest
RUN apt-get update && apt-get install python3-pip -y
WORKDIR /password-manager/
COPY . ./
RUN touch /password-manager/password_manager.db
RUN touch /password-manager/default_credentials.txt
RUN pip install -r requirements.txt --break-system-packages
EXPOSE 443/tcp
CMD python3 server.py