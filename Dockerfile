#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN go mod download

ARG PROJECT=github.com/sanya-spb/oneTimeInfo
ARG RELEASE=
ARG COMMIT=
ARG BUILD_TIME=
ARG COPYRIGHT="sanya-spb"
ARG CGO_ENABLED=1

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=${CGO_ENABLED} go build \
    -ldflags "-s -w \
    -X ${PROJECT}/pkg/version.version=${RELEASE} \
    -X ${PROJECT}/pkg/version.commit=${COMMIT} \
    -X ${PROJECT}/pkg/version.buildTime=${BUILD_TIME} \
    -X ${PROJECT}/pkg/version.copyright=${COPYRIGHT}" \
    -o /go/bin/app/otin-backend ./cmd/otin-backend/

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/app/otin-backend /app/otin-backend
COPY --from=builder /go/src/app/data /app/data
RUN adduser -SDH goapp
USER goapp
WORKDIR /app
ENTRYPOINT /app/otin-backend -config /app/data/conf/config.yaml -debug
LABEL Name=otin-backend
VOLUME ["/app/data"]
EXPOSE 8080/tcp
