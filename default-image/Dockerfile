FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        less \
        openssh-client \
        screen \
        sudo \
        unzip \
        vim-tiny \
        wget \
 && rm -rf /var/lib/apt/lists/*
