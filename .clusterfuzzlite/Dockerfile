FROM gcr.io/oss-fuzz-base/base-builder-python

# Install system dependencies if required
RUN apt-get update && apt-get install -y make build-essential

# Install testing dependencies
RUN pip3 install hypothesis pyinstaller

# Copy project source into the container (REPLACED PLACEHOLDER)
COPY . $SRC/mailjet-apiv3-python
WORKDIR $SRC/mailjet-apiv3-python

# Copy the build script into the $SRC root
COPY .clusterfuzzlite/build.sh $SRC/
