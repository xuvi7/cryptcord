build:
	go build -o ./server ./cmd/server
run:
	./server
clean:
	rm server