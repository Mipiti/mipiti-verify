# Digest-pinned so a rebuild of the same commit resolves the same base
# image. Dependabot (docker ecosystem) bumps the digest.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

COPY requirements-all.lock /tmp/requirements-all.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-all.lock

COPY . /action
RUN pip install --no-cache-dir --no-deps "/action[all]"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Hardening: run as non-root user (CTRL-14)
RUN useradd --create-home --shell /bin/bash verifier
USER verifier

ENTRYPOINT ["/entrypoint.sh"]
