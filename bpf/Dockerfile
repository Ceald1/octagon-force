FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev build-essential linux-tools-common bpftool make
WORKDIR /work

COPY . /work



RUN make

