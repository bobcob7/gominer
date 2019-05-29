all: gominer

gominer: gominer.wasm main.go
	go build -o gominer main.go

gominer.wasm: bundle/gominer.go
	GOOS=js GOARCH=wasm go build -o gominer.wasm bundle/gominer.go

run: gominer.wasm gominer
	./gominer

clean:
	rm -f gominer *.wasm