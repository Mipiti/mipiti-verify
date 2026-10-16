# Digest-pinned so a rebuild of the same commit resolves the same base
# image. Dependabot (docker ecosystem) bumps the digest.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

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
