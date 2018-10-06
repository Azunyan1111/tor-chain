start:
	make build
	echo "Change terminal. and do 'make send'"
	./server/main

build:
	go build -o server/main server/main.go
	go build -o client/main client/main.go

send:
	make build
	./client/main

clean:
	rm server/main
	rm client/main
	rm server/log.db
