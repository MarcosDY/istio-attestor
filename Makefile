.DEFAULT_GOAL := help
export GO111MODULE=on
binary_dirs := server
out_dir := bin

build: $(binary_dirs)

$(binary_dirs): noop
		cd $@ && go build -o ../$(out_dir)/$@  -i

utils: $(utils)

$(utils): noop
		go get $@

vendor:
		go mod vendor

test:
		go test -race

clean:
		go clean

noop:

.PHONY: all build vendor utils test clean
