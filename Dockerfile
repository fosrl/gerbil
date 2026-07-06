ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /gerbil

# Start a new stage from scratch
FROM alpine:3.24 AS runner

RUN apk add --no-cache iptables iproute2

COPY --from=builder /gerbil /usr/local/bin/
COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["gerbil"]
