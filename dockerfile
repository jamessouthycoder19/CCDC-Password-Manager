FROM ubuntu:latest
RUN apt-get update && apt-get install python3-pip -y
COPY . /password-manager/
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 443/tcp
CMD server.py