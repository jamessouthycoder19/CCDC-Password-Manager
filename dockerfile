FROM ubuntu:latest
RUN apt-get update && apt-get install python3-pip -y
WORKDIR /password-manager/
COPY . ./
RUN pip install -r requirements.txt --break-system-packages
EXPOSE 443/tcp
CMD python3 server.py