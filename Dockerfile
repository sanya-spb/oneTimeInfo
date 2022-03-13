#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN go mod download

ARG GOOS=linux
ARG GOARCH=amd64
ARG PROJECT=github.com/sanya-spb/oneTimeInfo
ARG COPYRIGHT="sanya-spb"
ARG CGO_ENABLED=1

RUN GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=$CGO_ENABLED go build \
    -ldflags "-s -w \
    -X $PROJECT/pkg/version.copyright=$COPYRIGHT" \
    -o /go/bin/app/otin-backend ./cmd/otin-backend/

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/app/otin-backend /otin-backend
COPY --from=builder /go/src/app/data /data
ENTRYPOINT /otin-backend -config ./data/conf/config.yaml
LABEL Name=otin-backend Version=0.0.1
EXPOSE 8181/tcp
