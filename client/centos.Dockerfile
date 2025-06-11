# Reference: https://docs.docker.com/reference/dockerfile/
FROM centos:7 AS builder

# https://serverfault.com/a/1161847
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo
RUN sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo

RUN yum update -y && yum install -y curl gcc
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- --default-toolchain=1.87 -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-generate-rpm

COPY . /app
WORKDIR /app

RUN cargo build -p rat-client --release
RUN cargo generate-rpm --payload-compress none -p client -o rat-client.rpm

FROM centos:7

# https://serverfault.com/a/1161847
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo && \
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo && \
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo

COPY --from=builder /app/rat-client.rpm /app/rat-client.rpm
RUN yum install -y /app/rat-client.rpm
