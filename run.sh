#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REGISTRY="${REGISTRY:-docker.io/andpra70}"
IMAGE_NAME="${IMAGE_NAME:-oauth-server}"
TAG="${TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-oauth-server}"
HOST_PORT="${HOST_PORT:-9000}"
CONTAINER_PORT="${CONTAINER_PORT:-9000}"
ENV_FILE="${ENV_FILE:-.env}"
DATA_DIR="${DATA_DIR:-$SCRIPT_DIR/data/oauth}"
PULL_IMAGE="${PULL_IMAGE:-true}"

IMAGE_REF="${REGISTRY}/${IMAGE_NAME}:${TAG}"

mkdir -p "${DATA_DIR}"

if docker container inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
  echo "Stopping existing container ${CONTAINER_NAME}"
  docker stop "${CONTAINER_NAME}" >/dev/null
  echo "Removing existing container ${CONTAINER_NAME}"
  docker rm "${CONTAINER_NAME}" >/dev/null
fi

if [[ "${PULL_IMAGE}" == "true" && "${IMAGE_REF}" == */* ]]; then
  echo "Pulling ${IMAGE_REF}"
  docker pull "${IMAGE_REF}"
fi

RUN_ARGS=(
  -d
  --name "${CONTAINER_NAME}"
  --restart unless-stopped
  -p "${HOST_PORT}:${CONTAINER_PORT}"
  -v "${DATA_DIR}:/app/data"
)

if [[ -f "${ENV_FILE}" ]]; then
  RUN_ARGS+=(--env-file "${ENV_FILE}")
fi

docker run "${RUN_ARGS[@]}" "${IMAGE_REF}" >/dev/null

echo "Container started"
echo "Container: ${CONTAINER_NAME}"
echo "Image: ${IMAGE_REF}"
echo "Port: ${HOST_PORT}->${CONTAINER_PORT}"
echo "Data dir: ${DATA_DIR}"
if [[ -f "${ENV_FILE}" ]]; then
  echo "Env file: ${ENV_FILE}"
else
  echo "Env file: not provided"
fi
