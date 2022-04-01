PROJECT?=github.com/sanya-spb/oneTimeInfo
PROJECTNAME=$(shell basename "$(PROJECT)")

TARGETOS?=linux
TARGETARCH?=amd64

CGO_ENABLED=1

RELEASE := $(shell git tag -l | tail -1 | grep -E "v.+"|| echo devel)
COMMIT := git-$(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COPYRIGHT := "sanya-spb"

## build: Build otin-backend
build:
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=${CGO_ENABLED} go build \
		-ldflags "-s -w \
		-X ${PROJECT}/pkg/version.version=${RELEASE} \
		-X ${PROJECT}/pkg/version.commit=${COMMIT} \
		-X ${PROJECT}/pkg/version.buildTime=${BUILD_TIME} \
		-X ${PROJECT}/pkg/version.copyright=${COPYRIGHT}" \
		-o ./cmd/otin-backend/otin-backend ./cmd/otin-backend/

## build: Build otin-backend docker image
image:
	docker build -t otin-backend \
	--build-arg RELEASE=${RELEASE} \
	--build-arg COMMIT=${COMMIT} \
	--build-arg BUILD_TIME=${BUILD_TIME} \
	.
	@echo "\n\nTo start container:"
	@echo 'docker run -dit --restart unless-stopped -p 8080:8080 -v $(pwd)/conf:/app/data/conf --name otin-backend otin-backend:latest'

## check: Run linters
check:
	golangci-lint -c ./.golangci.yml run

## run: Run otin-backend
run:
	go run ./cmd/otin-backend/ -config ./data/conf/config.yaml

## clean: Clean build files
clean:
	go clean
	rm -v ./cmd/otin-backend/otin-backend 2> /dev/null || true
	rm -v ./data/logs/*.log 2> /dev/null || true

## test: Run unit test
test:
	go test -v -short ${PROJECT}/cmd/otin-backend/

## integration: Run integration test
integration:
	# go test -v -run Integration ${PROJECT}/cmd/otin-backend/

## help: Show this
help: Makefile
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
