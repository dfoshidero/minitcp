# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM ubuntu:24.04

ARG USERNAME=netstack
ARG USER_UID=1001
ARG USER_GID=1001

LABEL org.opencontainers.image.source="https://github.com/dfoshidero/minitcp"

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME} \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iputils-ping \
        sudo \
        tcpdump \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/minitcp /usr/local/bin/minitcp
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/shell-rc.sh /usr/local/share/minitcp-shell.sh

USER netstack
WORKDIR /home/netstack
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
