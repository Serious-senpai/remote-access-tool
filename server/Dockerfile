# Reference: https://docs.docker.com/reference/dockerfile/
FROM rust:1.87 AS builder

RUN cargo install cargo-deb

COPY . /app
WORKDIR /app

RUN cargo deb -p rat-client -o rat-client.deb
RUN cargo deb -p rat-server -o rat-server.deb

FROM ubuntu:24.04

COPY --from=builder /app/rat-client.deb /app/rat-client.deb
COPY --from=builder /app/rat-server.deb /app/rat-server.deb
RUN apt-get update && apt-get install -y openssh-client /app/rat-client.deb /app/rat-server.deb
