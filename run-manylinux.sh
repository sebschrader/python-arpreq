#!/bin/bash

set -Eexuo pipefail

readonly -a PLATFORMS=(
	manylinux1_x86_64
	manylinux1_i686
	manylinux2010_x86_64
	manylinux2010_i686
)

export PLAT=
for PLAT in "${PLATFORMS[@]}"; do
	if [[ "${PLAT%%i686}" = "$PLAT" ]]; then
		PRE_CMD=
	else
		PRE_CMD=linux32
	fi
	docker-compose run --rm manylinux ${PRE_CMD} /io/docker/build-wheels.sh
done
