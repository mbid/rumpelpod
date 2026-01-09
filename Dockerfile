FROM debian:trixie

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install --yes \
        build-essential \
        make \
        cmake \
        pkg-config \
        git \
        curl \
        wget \
        ca-certificates \
        fish \
        sudo \
        locales \
        gnupg \
        docker.io \
        lighttpd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LO https://github.com/neovim/neovim/releases/latest/download/nvim-linux-x86_64.appimage && \
    chmod +x nvim-linux-x86_64.appimage && \
    ./nvim-linux-x86_64.appimage --appimage-extract && \
    mv squashfs-root /opt/nvim && \
    ln -s /opt/nvim/usr/bin/nvim /usr/local/bin/nvim && \
    ln -s /opt/nvim/usr/bin/nvim /usr/local/bin/vim && \
    rm nvim-linux-x86_64.appimage

# Create entrypoint that starts dockerd in background.
RUN printf '#!/bin/bash\n\
# Start dockerd in background if not already running\n\
if ! pgrep -x dockerd > /dev/null; then\n\
    sudo sh -c "dockerd > /var/log/dockerd.log 2>&1" &\n\
    # Wait for docker to be ready (max 30s)\n\
    for i in $(seq 1 30); do\n\
        if docker info > /dev/null 2>&1; then\n\
            break\n\
        fi\n\
        sleep 1\n\
    done\n\
    # Make socket world-accessible (needed because --user bypasses /etc/group)\n\
    sudo chmod 666 /var/run/docker.sock\n\
fi\n\
exec "$@"\n' > /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ARG USER_NAME=developer
ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd -g ${GROUP_ID} ${USER_NAME} || groupadd ${USER_NAME} && \
    useradd -m -u ${USER_ID} -g ${USER_NAME} -s /usr/bin/fish ${USER_NAME} && \
    echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    usermod -aG docker ${USER_NAME}

USER ${USER_NAME}
WORKDIR /home/${USER_NAME}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/${USER_NAME}/.cargo/bin:${PATH}"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
