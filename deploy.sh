#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REGISTRY="${REGISTRY:-docker.io/andpra70}"
IMAGE_NAME="${IMAGE_NAME:-oauth-server}"
TAG="${TAG:-latest}"
PUSH_IMAGE="${PUSH_IMAGE:-true}"

IMAGE_REF="${REGISTRY}/${IMAGE_NAME}:${TAG}"

echo "Building ${IMAGE_REF}"
docker build -t "${IMAGE_REF}" .

if [[ "${PUSH_IMAGE}" == "true" ]]; then
  echo "Pushing ${IMAGE_REF}"
  docker push "${IMAGE_REF}"
else
  echo "Skipping push because PUSH_IMAGE=${PUSH_IMAGE}"
fi

echo "Deploy completed"
echo "Image: ${IMAGE_REF}"
