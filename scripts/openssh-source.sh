#!/bin/bash
set -e

#! https://stackoverflow.com/a/246128
SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ROOT_DIR=$(realpath $SCRIPT_DIR/..)

mkdir -p $ROOT_DIR/keys
if [ ! -d "$ROOT_DIR/keys/openssh-portable" ]
then
    git clone --depth 1 https://github.com/openssh/openssh-portable $ROOT_DIR/keys/openssh-portable
fi

apt-get install -y autoconf libssl-dev zlib1g-dev

cd $ROOT_DIR/keys/openssh-portable
if [ ! -f "$ROOT_DIR/keys/openssh-portable/.configure"]
then
    autoconf
    ./configure
fi

make

if [ ! -d "/home/sshd" ]
then
    useradd -m sshd
fi

mkdir -p /var/empty /usr/local/libexec
ln -sf $ROOT_DIR/keys/openssh-portable/sshd-auth /usr/local/libexec/sshd-auth
ln -sf $ROOT_DIR/keys/openssh-portable/sshd-session /usr/local/libexec/sshd-session
yes | ssh-keygen -t rsa -f $ROOT_DIR/keys/host -N ""
$ROOT_DIR/keys/openssh-portable/sshd -De -f $ROOT_DIR/scripts/sshd_config -h $ROOT_DIR/keys/host
