# Build environment for the Linux desktop app (age-tool-gui).
#
# The GUI uses Fyne, which needs CGO and the OpenGL/X11 development
# libraries, so it can't be cross-compiled like the static CLI. Instead it
# is built inside this container, once per architecture:
#
#   docker buildx build --platform linux/amd64 -t age-tool-linux-build:amd64 --load packaging/linux
#
# Ubuntu 22.04 is used on purpose: a binary built against an older C
# library (glibc) runs on newer distributions, but not the other way round.
# Its glibc 2.35 covers Ubuntu 22.04 LTS and later and current Fedora, Mint,
# Kubuntu and Xubuntu releases. (Debian 11 would reach further back, but its
# packages have left the main mirrors since it reached end of life.)
FROM ubuntu:22.04

# Go version to build with; keep in step with go.mod
ARG GO_VERSION=1.26.11
# Set automatically by buildx from --platform (amd64 or arm64)
ARG TARGETARCH

# C compiler and the headers Fyne's window driver (GLFW 3.4) builds
# against: OpenGL, X11, and Wayland (GLFW picks X11 or Wayland at run time,
# so the app works in either kind of desktop session)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl gcc libc6-dev pkg-config libgl1-mesa-dev \
      libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev \
      libxxf86vm-dev libwayland-dev libxkbcommon-dev wayland-protocols \
 && rm -rf /var/lib/apt/lists/*

# Install Go from the official download, verifying its published SHA256
RUN set -eu; \
    file="go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    curl -fsSLO "https://dl.google.com/go/${file}"; \
    echo "$(curl -fsSL "https://dl.google.com/go/${file}.sha256")  ${file}" | sha256sum -c -; \
    tar -C /usr/local -xzf "${file}"; \
    rm "${file}"

# Use exactly this Go, with CGO on for Fyne
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1

WORKDIR /src
