FROM quay.io/cilium/bpftool:latest AS bpftool-provider

# Stage 2: Your actual container
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Copy bpftool from Stage 1 into /usr/local/bin
COPY --from=bpftool-provider /usr/local/bin/bpftool /usr/local/bin/bpftool

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

