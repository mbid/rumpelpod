ARG BASE_IMAGE=debian:trixie

FROM $BASE_IMAGE

USER root

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install --yes \
        systemd \
        systemd-sysv \
        libsystemd0 \
        dbus \
        kmod \
        iptables \
        iproute2 \
        udev \
        build-essential \
        make \
        cmake \
        pkg-config \
        git \
        git-lfs \
        curl \
        wget \
        ca-certificates \
        sudo \
        locales \
        gnupg \
        docker.io \
        kubectl \
        kind \
        screen \
        musl-tools \
        skopeo

RUN echo "ReadKMsg=no" >> /etc/systemd/journald.conf \
    && systemctl mask \
        proc-sys-fs-binfmt_misc.automount \
        apparmor.service \
        tmp.mount \
        systemd-udevd.service \
        systemd-sysctl.service \
        systemd-udevd-kernel.socket \
        systemd-udevd-control.socket \
        systemd-modules-load.service \
        sys-kernel-debug.mount \
        sys-kernel-tracing.mount \
        sys-kernel-config.mount \
        e2scrub_reap.service \
        e2scrub_all.timer

STOPSIGNAL SIGRTMIN+3

ARG USER=dev
ARG USER_ID=1000
ARG GROUP_ID=1000

ENV USER=${USER}
ENV USER_ID=${USER_ID}
ENV GROUP_ID=${GROUP_ID}

# Ensure the user and group exist, handling the case where the base image
# already provides them (possibly with a different uid/gid/shell).
RUN if ! getent group ${USER} > /dev/null 2>&1; then \
        groupadd -g ${GROUP_ID} ${USER} || groupadd ${USER}; \
    fi && \
    if ! id -u ${USER} > /dev/null 2>&1; then \
        useradd -m -u ${USER_ID} -g ${USER} ${USER}; \
    fi && \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    usermod -aG docker ${USER}

USER ${USER}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/${USER}/.cargo/bin:${PATH}"
RUN rustup component add rust-analyzer \
    && rustup target add x86_64-unknown-linux-musl

RUN curl -fsSL https://claude.ai/install.sh | bash

USER root
RUN mkdir /workspaces && chown -R ${USER}:${USER} /workspaces
USER ${USER}

RUN git clone https://github.com/mbid/rumpelpod /workspaces/rumpelpod
WORKDIR /workspaces/rumpelpod

# Initialize cargo crate registry, populate target/ so that incremental builds will be fast.
RUN cargo build; cargo test --no-run; true

USER root

# Pre-download test base image so tests don't depend on Docker Hub availability.
RUN mkdir /preloaded-images \
    && skopeo copy docker://docker.io/library/debian:13 docker-archive:/preloaded-images/debian-13.tar:debian:13

RUN printf '[Unit]\nAfter=docker.service\nRequires=docker.service\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/docker load -i /preloaded-images/debian-13.tar\n\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/preload-images.service \
    && systemctl enable preload-images.service

ENTRYPOINT ["/sbin/init"]
