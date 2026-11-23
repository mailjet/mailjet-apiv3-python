FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends make build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install testing dependencies
RUN pip3 install --no-cache-dir \
    hypothesis==6.170.15 \
    httpx2==2.16.2 \
    pyinstaller==6.13.0 \
    requests==2.34.2 \
    typing-extensions==4.16.0

# Copy project source into the container
COPY . "$SRC/mailjet-apiv3-python"
WORKDIR "$SRC/mailjet-apiv3-python"

# Copy the build script into the $SRC root
COPY .clusterfuzzlite/build.sh "$SRC/"

# hadolint ignore=DL3002
# checkov:skip=CKV_DOCKER_3:ClusterFuzzLite compile requires root to write /usr/lib/libFuzzingEngine.a
# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root
USER root
