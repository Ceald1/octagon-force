FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive




# 1. Install standard build tools and dependencies (omit linux-tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        build-essential \
        make \
        ca-certificates \
        curl \
        sudo && \
    rm -rf /var/lib/apt/lists/*

# 2. Download and install independent standalone bpftool
RUN curl -L https://github.com/libbpf/bpftool/releases/download/v7.4.0/bpftool-v7.4.0-amd64.tar.gz | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/bpftool
#RUN apt update && \
#    apt install -y --no-install-recommends \
#        clang \
#        llvm \
#        libelf-dev \
#        libbpf-dev \
#        build-essential \
#        linux-tools-common \
#        linux-tools-generic \
#        make sudo && \
#    rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY . .



RUN make

CMD ["make", "loadall"]

