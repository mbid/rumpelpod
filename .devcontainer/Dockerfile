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
        curl \
        wget \
        ca-certificates \
        sudo \
        locales \
        gnupg \
        docker.io \
        kubectl \
        kind \
        screen

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

RUN curl -fsSL https://claude.ai/install.sh | bash

USER root
RUN mkdir /workspaces && chown -R ${USER}:${USER} /workspaces
USER ${USER}

RUN git clone https://github.com/mbid/sandbox /workspaces/sandbox
WORKDIR /workspaces/sandbox

ARG ANTHROPIC_API_KEY
ARG XAI_API_KEY
ARG GEMINI_API_KEY

ENV ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
ENV XAI_API_KEY=${XAI_API_KEY}
ENV GEMINI_API_KEY=${GEMINI_API_KEY}

# Initialize cargo crate registry, populate target/ so that incremental builds will be fast.
RUN cargo build; cargo test --no-run; true

USER root

ENTRYPOINT ["/sbin/init"]
