FROM debian:testing

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
        vim \
        wget \
 && rm -rf /var/lib/apt/lists/*
