FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends make build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install testing dependencies
RUN pip3 install --no-cache-dir hypothesis httpx2 pyinstaller

# Copy project source into the container
COPY . "$SRC/mailjet-apiv3-python"
WORKDIR "$SRC/mailjet-apiv3-python"

# Copy the build script into the $SRC root
COPY .clusterfuzzlite/build.sh "$SRC/"

# Drop root privileges for fuzzer build execution
RUN useradd --create-home --uid 10001 fuzzer \
    && mkdir -p "$SRC" "$OUT" "$WORK" \
    && chown -R fuzzer:fuzzer /usr/local "$SRC" "$OUT" "$WORK"
# hadolint ignore=DL3002
# checkov:skip=CKV_DOCKER_3:ClusterFuzzLite compile requires root to write /usr/lib/libFuzzingEngine.a
# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root
USER root
