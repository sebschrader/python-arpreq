#!/bin/bash
set -exuo pipefail

cache_dir=/io/wheelhouse/pip-cache
cd /opt/python
readonly -a versions=(*)
cd "${HOME}"

# Compile wheels
for version in "${versions[@]}"; do
    if [[ -x "/opt/python/${version}/bin/virtualenv" ]]; then
        declare -a venv=("/opt/python/${version}/bin/virtualenv" --system-site-packages --without-pip)
    else
        declare -a venv=("/opt/python/${version}/bin/python" -m venv --system-site-packages --without-pip)
    fi
    "${venv[@]}" "${version}"
    "${version}/bin/python" -m pip install --cache-dir "${cache_dir}" -r /io/dev-requirements.txt
    "${version}/bin/python" -m pip wheel /io/ --no-deps
done

# Bundle external shared libraries into the wheels
for wheel in *.whl; do
    auditwheel repair "$wheel" --plat "$PLAT" -w /io/wheelhouse/
done

# Install packages and test
for version in "${versions[@]}"; do
    "${version}/bin/python" -m pip install arpreq --no-index -f /io/wheelhouse
    "${version}/bin/python" -m pytest /io/tests -v
done
