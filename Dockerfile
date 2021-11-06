FROM golang:1.17.1

WORKDIR /go/src/app
COPY . .

RUN go install github.com/cosmtrek/air@latest

# CMD go mod tidy && air -c .air.toml
