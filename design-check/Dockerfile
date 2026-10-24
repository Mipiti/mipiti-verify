# Mipiti design check tools
#
# The checkers a design proof bundle is re-checked with:
#
#   mipiti-verify design-bundle <bundle.tar.gz> --recheck
#
# runs every certificate's Apalache checks and every proof's tlapm run in this
# image. The image holds only these tools, built from public upstream sources
# at the versions the bundle's certificates and proofs name:
#
#   /tools/apalache        Apalache 0.62.4 (symbolic model checker)
#   /tools/tlapm           TLA+ Proof System, with the Zenon and LS4 back ends
#   /tools/bin/z3          Z3, the SMT back end tlapm calls
#   /tools/tla2tools.jar   TLC and SANY 1.7.4
#
# and a Java 21 runtime. Every download is pinned by commit or checked against
# its published SHA-256, and every base image is pinned by digest, so building
# this file again gives the same tools. The image needs no network and holds no
# credential; mipiti-verify runs it with the network off, as an unprivileged
# user, on a copy of the files it checks.

# tlapm, built from a pinned upstream commit. Two of its bundled back ends are
# left out. Isabelle: every proof is checked with an explicit back-end list,
# --method smt:600,zenon,ls4 (the re-check passes the same list), and tlapm calls
# no back end outside it, so a step only Isabelle could close stays open and
# that proof is not reported as proved. The x86-only Z3 binary: Z3 is built
# below, for both architectures. The LS4 patch limits an x87 floating-point
# setting to x86, so LS4 builds on arm64. The changes are committed with a
# fixed author, date and message: the commit's hash is what `tlapm --version`
# prints, and each proof in a bundle names that build (3edc73c), so the
# re-check runs exactly the prover the proof was checked with.
FROM ocaml/opam:debian-12-ocaml-5.1@sha256:441d5fcf1d8d9d1ffab06b651f6bf9f87c4562c3b9d7adf774dbb876d503acc5 AS tlapm-build
ARG TLAPM_COMMIT=d8b9747a1dce9b4816bcc1ff130ccf7a3af2ce37
RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends \
      zlib1g-dev gawk time wget unzip patch g++ pkg-config make \
    && sudo rm -rf /var/lib/apt/lists/*
WORKDIR /home/opam/tlapm
COPY --chown=opam:opam tlapm-ls4-fpu.patch /home/opam/tlapm-ls4-fpu.patch
RUN git init -q . && git fetch -q --depth 1 https://github.com/tlaplus/tlapm.git "$TLAPM_COMMIT" \
    && git -c advice.detachedHead=false checkout -q FETCH_HEAD \
    && rm -rf deps/isabelle deps/z3 \
    && cat /home/opam/tlapm-ls4-fpu.patch >> deps/ls4/ls4.patch \
    && sed -i 's#releases/latest/download/CommunityModules.jar#releases/download/202610040242/CommunityModules.jar#' library/dune \
    && grep -q 'releases/download/202610040242/CommunityModules.jar' library/dune \
    && git add -A \
    && GIT_AUTHOR_DATE=2026-10-06T17:48:43Z GIT_COMMITTER_DATE=2026-10-06T17:48:43Z \
       git -c user.name=formal -c user.email=formal@invalid commit -q \
         -m "The formal suite's build: no Isabelle, no bundled Z3, LS4 on arm64, pinned community modules"
RUN opam install ./ --deps-only --yes
RUN opam exec -- dune build -p tlapm @install \
    && echo "b7fcd727fc5135a628e56d5015651c74ba70681bbaf88df1cd59e9afa64215ad  _build/default/library/CommunityModules.jar" | sha256sum -c - \
    && echo "2d3fff1637497971cf00287df1a6cbb572769a61d10a86e0d11d34d39a017b1d  _build/default/deps/ls4/v1.0.zip" | sha256sum -c - \
    && opam exec -- dune install -p tlapm --relocatable --prefix _build/tlapm

# Z3 5.3.0, built from its pinned release commit and linked statically. A
# proof's back ends are bounded by Z3's resource count rather than a clock, so
# a step closes or not the same way on every machine and architecture.
FROM --platform=$BUILDPLATFORM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS z3-build
ARG TARGETARCH
ARG BUILDARCH
ARG Z3_COMMIT=2e8d6ed8043aa8bd05c988cf0bd95c66396f47d7
RUN set -e; \
    case "$TARGETARCH" in \
      amd64) triplet=x86_64-linux-gnu; cpu=x86_64; machine="X86-64"; cross=g++-x86-64-linux-gnu ;; \
      arm64) triplet=aarch64-linux-gnu; cpu=aarch64; machine="AArch64"; cross=g++-aarch64-linux-gnu ;; \
      *) echo "no Z3 build for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" = "$BUILDARCH" ]; then compiler=g++; system=""; \
    else compiler="$cross"; system="-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=$cpu"; fi; \
    apt-get update && apt-get install -y --no-install-recommends \
      cmake make git ca-certificates binutils "$compiler" \
    && rm -rf /var/lib/apt/lists/*; \
    git init -q /z3 && cd /z3; \
    git fetch -q --depth 1 https://github.com/Z3Prover/z3.git "$Z3_COMMIT"; \
    git -c advice.detachedHead=false checkout -q FETCH_HEAD; \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DZ3_BUILD_LIBZ3_SHARED=OFF \
      -DZ3_BUILD_TEST_EXECUTABLES=OFF -DCMAKE_EXE_LINKER_FLAGS=-static $system \
      -DCMAKE_C_COMPILER="$triplet-gcc" -DCMAKE_CXX_COMPILER="$triplet-g++" >/dev/null; \
    cmake --build build -j"$(nproc)" >/dev/null; \
    readelf -h build/z3 | grep -q "Machine:.*$machine"; \
    ! readelf -l build/z3 | grep -q INTERP; \
    mkdir /out && cp build/z3 /out/z3 && rm -rf /z3

# TLC and Apalache, the release archives, each checked against its SHA-256.
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS fetch
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q -O /tla2tools.jar \
      https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
    && echo "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88  /tla2tools.jar" | sha256sum -c -
RUN wget -q -O /apalache.tgz \
      https://github.com/apalache-mc/apalache/releases/download/v0.62.4/apalache.tgz \
    && echo "8ac8488422c30d552735bae11b92a2d014d8e02e8608702acc08f9a2d8a9abb2  /apalache.tgz" | sha256sum -c - \
    && tar -xzf /apalache.tgz -C / \
    && test -f /apalache/lib/apalache.jar && test -x /apalache/bin/apalache-mc

# The image: the tools above, a Java 21 runtime (Apalache needs it), and procps
# (tlapm reads it at start), run as an unprivileged user.
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jre-headless procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tlapm-build /home/opam/tlapm/_build/tlapm /tools/tlapm
COPY --from=z3-build /out/z3 /tools/bin/z3
COPY --from=fetch /tla2tools.jar /tools/tla2tools.jar
COPY --from=fetch /apalache /tools/apalache
ENV PATH=/tools/tlapm/bin:/tools/bin:/tools/apalache/bin:$PATH \
    APALACHE_JAR=/tools/apalache/lib/apalache.jar \
    TLAPM=/tools/tlapm/bin/tlapm
RUN useradd --create-home --uid 1001 checker && mkdir /work && chown checker:checker /work
USER checker
WORKDIR /work
