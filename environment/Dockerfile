FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    ruby \
    libssl-dev \
    pkg-config \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip3 install --break-system-packages pytest==8.0.0

# Ensure /var/log/syslog exists and is world-writable for tests
RUN mkdir -p /var/log && touch /var/log/syslog && chmod 666 /var/log/syslog

WORKDIR /app