# RIT CCDC's Password-Manager

This tool was made to attempt to un-gamify our tools. The password_manager.db is an empty database, so that the docker container will be setup correctly. This file volume'd into the docker container, that way the password database will persist in between restarts of the underlying OS.

To run the server
```
$ sudo docker compose up
```

To compile the agents

Windows
```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o windows.exe main.go
```
Linux
```
GOOS=linux GOARCH=amd64 go build -ldflags '-linkmode external -extldflags "-static"' -o linux  main.go
```

To tell git no to track any changes to the password_manager.db file
```
git update-index --assume-unchanged example.txt
```