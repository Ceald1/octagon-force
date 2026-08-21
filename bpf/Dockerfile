FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive




RUN apt update && \
    apt install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        build-essential \
        linux-tools-common \
        linux-tools-generic \
        make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY . /work



RUN cd /work && make

