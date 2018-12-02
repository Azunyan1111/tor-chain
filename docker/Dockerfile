FROM ubuntu:16.04

# install app
RUN apt-get update && apt-get upgrade -y
RUN apt-get install wget gcc libevent-dev libssl-dev make unzip -y
RUN apt-get update && apt-get upgrade -y
RUN apt-get install golang-1.10 git -y
RUN export PATH="/usr/lib/go-1.10/bin:$PATH"


# open port
EXPOSE 80
EXPOSE 443

# get Tor file
RUN wget https://www.torproject.org/dist/tor-0.3.4.9.tar.gz

# Create Tor
RUN tar -xvf tor-0.3.4.8.tar.gz
WORKDIR tor-0.3.4.8/
RUN ./configure && make
WORKDIR /

# Create torrc file
RUN mkdir /etc/tor/
RUN echo "ORPort 443\nDirPort 80\nExitRelay 0\nExitPolicy reject *:*" >> /etc/tor/torrc

# run tor node
RUN /tor-0.3.4.8/src/or/tor -f /etc/tor/torrc & >> /etc/tor/torlog

# pkttols
WORKDIR /
RUN wget http://kozos.jp/software/pkttools-1.16.zip
RUN unzip pkttools-1.16.zip
WORKDIR pkttools-1.16/
RUN make

# PORT
EXPOSE 8585
EXPOSE 80
EXPOSE 443

# WORKDIR /go/src/github.com/Azunyan1111/tor-chain/app/

# ここでGolangのアプリを起動する。


# パケットをファルタしてTorのパケットのみを取得する。(ここはgolangで取得する
#CMD ./pkt-recv -i eth0 TCP.SRC_PORT==60000 | ./pkt-txt2txt ETHERNET.TYPE==0x0800

# SYN パケットのみを抽出する文章
#./pkt-recv -i en0 TCP.SRC_PORT==443 | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x002 # SYN
#./pkt-recv -i en0 TCP.SRC_PORT==0x1bb | ./pkt-txt2txt ETHERNET.TYPE==0x0800 | ./pkt-txt2txt TCP.FLAGS==0x011 # FIN ACK