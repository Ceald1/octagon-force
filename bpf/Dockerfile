FROM ghcr.io/libbpf/bpftool:latest AS bpftool-provider

# Stage 2: Build environment
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Copy bpftool executable from Stage 1
COPY --from=bpftool-provider /usr/bin/bpftool /usr/local/bin/bpftool

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        build-essential \
        make \
        sudo && \
    rm -rf /var/lib/apt/lists/*


WORKDIR /work

COPY . .



RUN make

CMD ["make", "loadall"]

