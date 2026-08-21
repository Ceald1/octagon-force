FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive




RUN apt update && \
    apt install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        build-essential \
        linux-tools-common \
        linux-tools-generic \
        make sudo && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY . .



RUN make

CMD ["make", "loadall"]

