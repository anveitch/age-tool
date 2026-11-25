# Build environment for the Linux desktop app (age-tool-gui).
#
# The GUI uses Fyne, which needs CGO and the OpenGL/X11 development
# libraries, so it can't be cross-compiled like the static CLI. Instead it
# is built inside this container, once per architecture:
#
#   docker buildx build --platform linux/amd64 -t age-tool-linux-build:amd64 --load packaging/linux
#
# build-gui.sh (next to this file) does that automatically, then builds the
# AppImage. It also packs the AppImage here, so the container includes the
# SquashFS tools and the AppImage runtime.
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
      libxxf86vm-dev libwayland-dev libxkbcommon-dev wayland-protocols squashfs-tools \
 && rm -rf /var/lib/apt/lists/*

# Install Go from the official download, verifying its published SHA256
RUN set -eu; \
    file="go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    curl -fsSLO "https://dl.google.com/go/${file}"; \
    echo "$(curl -fsSL "https://dl.google.com/go/${file}.sha256")  ${file}" | sha256sum -c -; \
    tar -C /usr/local -xzf "${file}"; \
    rm "${file}"

# The AppImage runtime: the small program at the start of every AppImage
# that mounts the app's files and starts it. This is the official
# type2-runtime release 20251108. Its hashes were taken from files whose GPG
# signatures were checked against the AppImage project's runtime signing
# key, so the download is verified here against those exact files.
ARG APPIMAGE_RUNTIME=20251108
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) arch=x86_64;  sum=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d ;; \
      arm64) arch=aarch64; sum=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444 ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/appimage; \
    curl -fsSLo /opt/appimage/runtime "https://github.com/AppImage/type2-runtime/releases/download/${APPIMAGE_RUNTIME}/runtime-${arch}"; \
    echo "${sum}  /opt/appimage/runtime" | sha256sum -c -

# Use exactly this Go, with CGO on for Fyne
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1

WORKDIR /src
