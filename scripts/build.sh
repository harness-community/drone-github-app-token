#!/bin/bash

set -e

cd "$(dirname "$0")/.."

# Download dependencies
go mod download

# Build binary
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o drone-github-app-token .

echo "Build complete: $(pwd)/drone-github-app-token"
