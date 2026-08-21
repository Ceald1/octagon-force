FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive



RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        build-essential \
        linux-tools-common \
        bpftool \
        make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY . /work



RUN make

