export GO111MODULE=on
out_dir := bin

build:
		go build -i

vendor:
		go mod vendor

test:
		go test -race ./..

noop:

.PHONY: all build vendor utils test clean
