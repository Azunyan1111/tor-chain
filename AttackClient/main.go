package main

import (
	"log"
	"net/http"
)

func main() {
	i := 100
	for i > 0{
		log.Println("send count",i)
		if i % 10 == 0{
			SendBadRequest()
		}else{
			SendGoodRequest()
		}
		i--
	}
	SendBadRequest()
}

func SendBadRequest(){
	_,err := http.Get("http://localhost:8000?ip=192.168.1.2&data=xss")
	if err != nil{
		panic(err)
	}
}

func SendGoodRequest(){
	_,err := http.Get("http://localhost:8000?ip=192.168.1.1")
	if err != nil{
		panic(err)
	}
}