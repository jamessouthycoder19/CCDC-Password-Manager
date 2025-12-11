FROM ubuntu:latest
RUN apt-get update && apt-get install python3-pip -y
COPY . /password-manager/
RUN pip install -r /password-manager/requirements.txt --break-system-packages
EXPOSE 443/tcp
CMD python3 /password-manager/server.py