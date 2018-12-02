# 攻撃スタート
start:
	make build
	./server/main
# コンパイル
build:
	go build -o server/main server/main.go
	go build -o client/main client/main.go
# リクエスト送信
send:
	make build
	./client/main
# コンパイルしたファイル等削除
clean:
	rm server/main
	rm client/main
	rm server/log.db

# ビルド
up:
	docker-compose up --build