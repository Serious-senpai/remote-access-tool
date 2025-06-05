# Reference: https://docs.docker.com/reference/dockerfile/
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git

RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- --default-toolchain=1.87 -y

ENV PATH="/root/.cargo/bin:${PATH}"

# https://stackoverflow.com/a/63348989
RUN rustup toolchain install nightly
