# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o llmass

# Final stage
FROM alpine:latest

WORKDIR /app

# Add testing repository for additional packages
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    echo "https://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories



# Install base utilities and screen
RUN apk add --no-cache \
    bash \
    curl \
    screen \
    && ln -sf /bin/bash /bin/sh

# Install base utilities and screen
RUN apk add --no-cache \
    bash \
    curl \
    screen \
    && ln -sf /bin/bash /bin/sh

# Install penetration testing tools and set up Python virtual environment
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    netcat-openbsd \
    bind-tools \
    openssh \
    openssl \
    tcpdump \
    socat \
    wget \
    hydra \
    python3 \
    py3-pip \
    py3-virtualenv \
    sqlite \
    postgresql-client \
    masscan \
    wireshark-common \
    aircrack-ng

# Set up Python virtual environment and install packages
RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir \
        requests \
        paramiko \
        scapy \
        impacket && \
    deactivate

# Add virtual environment to PATH
ENV PATH="/opt/venv/bin:$PATH"



# Copy binary from builder
COPY --from=builder /app/llmass .
COPY --from=builder /app/README.md .
COPY --from=builder /app/CONTEXT.md .

# Create sessions directory
RUN mkdir -p sessions

# Set environment variables
ENV PORT=8083
ENV SESSIONS_DIR=sessions

# Expose the port
EXPOSE 8083

# Run the application
CMD ["./llmass"]
