FROM golang:1.22 as build

WORKDIR /go/src/app
COPY . .

# Download dependencies
RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o drone-github-app-token .

# Create minimal container
FROM alpine:3.18

RUN apk add --no-cache ca-certificates

COPY --from=build /go/src/app/drone-github-app-token /bin/
ENTRYPOINT ["/bin/drone-github-app-token"]
