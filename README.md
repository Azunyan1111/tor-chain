# tor-chain

This is fit.ac.jp project.

This application makes it possible to specify the caller by managing the communication log by the block chain technology

## Get Started
※WARNING:In order to activate the relay node, it is necessary to release the numbers 80 and 443 port.

Dokcer and Docker-compose are required to operate this application.

```$xslt
make up
```

#### Install docker and docker-compose to ubuntu
```$xslt
apt-get install docker.io
apt-get install docker-compose
```

## Activate the exercise server to be attacked.
Installation of Golang is necessary for the operation of the exercise server.


##### Ubuntu
```$xslt
apt-get update
apt-get install -y gcc make
apt-get install -y golang-1.10
/usr/lib/go-1.10/bin/go help
```

####Start server
Start the exercise server.
```.sh
make start
```

#### Send Request
Send an HTTP GET request 100 times to the exercise server.
Send XSS request once every ten times.

Assume RUI "data = xss" as a malicious request.

WARNING:When sending via "Tor", it is necessary to indicate socket port 9050.(Default setting)
```.sh
make send
```
#### show log
You can access the log file with HTTP GET / log.
```.sh
http://loclhost:8000/log
```
