#!/usr/bin/env bash
#
# Smoke-test the image the release actually ships.
#
# `make docker-build` / the e2e suite build `Dockerfile`. The release builds
# `Dockerfile.goreleaser`, which until GRA-651 nothing built until a tag fired —
# the first time that image existed was in production, on the household's DNS.
# This script is the check that makes that no longer true: it starts the
# goreleaser-built image under the same securityContext the Helm chart applies
# and refuses to pass unless the container serves DNS and the admin SPA.
#
# Usage:
#   scripts/smoke-release-image.sh [image]
#
# With no argument the image and the host-side probe binary are read out of
# dist/artifacts.json, i.e. whatever `goreleaser release --snapshot` just built.

set -euo pipefail

DIST_DIR="${DIST_DIR:-dist}"
ARTIFACTS="$DIST_DIR/artifacts.json"

DNS_PORT="${SMOKE_DNS_PORT:-15353}"
HTTP_PORT="${SMOKE_HTTP_PORT:-14000}"
CONTAINER="${SMOKE_CONTAINER:-blockasaurus-release-smoke}"
VOLUME="${SMOKE_VOLUME:-blockasaurus-release-smoke-cache}"
WORK_DIR="$(mktemp -d)"

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

cleanup() {
  local rc=$?
  if [ $rc -ne 0 ] && docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo; echo "--- container logs ---" >&2
    docker logs "$CONTAINER" >&2 2>&1 || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  # Explicit: a bare `return` from an EXIT trap leaves the script's exit status
  # up to the last command the trap happened to run.
  exit $rc
}
trap cleanup EXIT

command -v jq >/dev/null || fail "jq is required"
command -v docker >/dev/null || fail "docker is required"
[ -f "$ARTIFACTS" ] || fail "$ARTIFACTS not found — run 'make release-image-snapshot' first"

artifact() { # $1 = jq select expression, $2 = field
  jq -r "first(.[] | select($1) | .$2) // empty" "$ARTIFACTS"
}

# Matched on the tag suffix rather than on goreleaser's goarch field, because
# the suffix is ours — it comes from image_templates in .goreleaser.yml — and
# the field is an implementation detail of whatever goreleaser version ran.
IMAGE="${1:-$(artifact '.type=="Docker Image" and (.name|endswith("-amd64"))' name)}"
[ -n "$IMAGE" ] || fail "no amd64 Docker Image artifact in $ARTIFACTS"

ARM_IMAGE="$(artifact '.type=="Docker Image" and (.name|endswith("-arm64"))' name)"
PROBE="$(artifact '.type=="Binary" and .goos=="linux" and .goarch=="amd64"' path)"

echo "image:     $IMAGE"
echo "arm image: ${ARM_IMAGE:-<none>}"
echo "probe:     ${PROBE:-<none>}"

# ---------------------------------------------------------------------------
# 1. Architecture. goreleaser cross-compiles per arch but `docker build` stamps
#    the image config with the BUILDER's platform unless --platform says
#    otherwise, so an arm64 binary can ship inside an amd64-labelled image and
#    the manifest list will hand it to an amd64 node. A build-only gate never
#    sees this; the image config does.
# ---------------------------------------------------------------------------
step "image architecture"
for pair in "$IMAGE:amd64" "${ARM_IMAGE:+$ARM_IMAGE:arm64}"; do
  [ -n "$pair" ] || continue
  img="${pair%:*}"; want="${pair##*:}"
  got="$(docker image inspect --format '{{.Architecture}}' "$img")"
  [ "$got" = "$want" ] || fail "$img declares architecture '$got', expected '$want'"
  echo "ok: $img -> $got"
done

# ---------------------------------------------------------------------------
# 2. File capability. `Dockerfile` gets this from `make build` (BIN_AUTOCAB);
#    Dockerfile.goreleaser has to do it in its own prep stage. Asserted rather
#    than inferred from a successful bind, because container runtimes differ in
#    whether they hand the process an effective capability set of its own — a
#    bind that works on Docker can still fail under a stricter runtime.
#    `scratch` has no shell, so the check borrows one.
# ---------------------------------------------------------------------------
step "cap_net_bind_service on /app/blockasaurus"
cat > "$WORK_DIR/capcheck.Dockerfile" <<DOCKERFILE
FROM $IMAGE AS rel
FROM alpine:3
RUN apk add --no-cache libcap
COPY --from=rel /app/blockasaurus /check/blockasaurus
RUN getcap /check/blockasaurus; getcap /check/blockasaurus | grep -q cap_net_bind_service
DOCKERFILE
if ! docker build -f "$WORK_DIR/capcheck.Dockerfile" -t blockasaurus-smoke-capcheck \
     "$WORK_DIR" > "$WORK_DIR/capcheck.log" 2>&1; then
  cat "$WORK_DIR/capcheck.log" >&2
  fail "/app/blockasaurus has no cap_net_bind_service — setcap was skipped, or the capability did not survive COPY --from"
fi
grep -o 'cap_net_bind_service=[a-z+]*' "$WORK_DIR/capcheck.log" | tail -n1 || true
docker rmi -f blockasaurus-smoke-capcheck >/dev/null 2>&1 || true
echo "ok"

# ---------------------------------------------------------------------------
# 3. Start it. Flags mirror packaging/helm/.../values.yaml securityContext plus
#    the named-volume mount the compose path uses:
#      --user 100 / --cap-drop ALL / --cap-add NET_BIND_SERVICE  -> the chart
#      --sysctl net.ipv4.ip_unprivileged_port_start=1024         -> Kubernetes
#    Docker sets that sysctl to 0 by default, which lets ANY uid bind :53 and
#    would hide a missing capability. Kubernetes does not, so neither do we.
#    databasePath lives on the mounted volume on purpose: it is also the check
#    that the seeded, uid-100-owned /app/cache survived into this image.
# ---------------------------------------------------------------------------
step "start container"
cat > "$WORK_DIR/config.yml" <<'CONFIG'
# Deliberately close to packaging/config/config.yml — the config the deb/rpm
# install — with databasePath moved onto the volume mount.
databasePath: /app/cache/smoke.db

ports:
  dns: 53
  http: 4000

log:
  level: info
CONFIG

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null

docker run -d --name "$CONTAINER" \
  --user 100 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
  -v "$VOLUME:/app/cache" \
  -v "$WORK_DIR/config.yml:/app/config.yml:ro" \
  -p "127.0.0.1:$DNS_PORT:53/udp" \
  -p "127.0.0.1:$DNS_PORT:53/tcp" \
  -p "127.0.0.1:$HTTP_PORT:4000" \
  "$IMAGE" >/dev/null

# ---------------------------------------------------------------------------
# 4. DNS, from inside, using the image's own binary — the same command the
#    image's HEALTHCHECK runs, so this covers that instruction too.
#    healthcheck.blocky is answered by the server itself and needs no upstream.
# ---------------------------------------------------------------------------
step "DNS answers on :53 (in-container healthcheck)"
ready=
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" /app/blockasaurus healthcheck >/dev/null 2>&1; then
    ready=1
    break
  fi
  docker inspect -f '{{.State.Running}}' "$CONTAINER" | grep -q true \
    || fail "container exited before it served DNS"
  sleep 1
done
[ -n "$ready" ] || fail "no DNS answer on :53 after 60s"
echo "ok"

# ---------------------------------------------------------------------------
# 5. DNS, from outside, over the published port. Uses the release's own linux
#    binary as the client so the check does not depend on dig being installed.
# ---------------------------------------------------------------------------
if [ -n "${PROBE:-}" ] && [ -x "$PROBE" ]; then
  step "DNS answers on the published port ($DNS_PORT)"
  "$PROBE" healthcheck -b 127.0.0.1 -p "$DNS_PORT" || fail "no DNS answer on 127.0.0.1:$DNS_PORT"
else
  fail "no linux/amd64 binary artifact to probe with (looked in $ARTIFACTS)"
fi

# ---------------------------------------------------------------------------
# 6. Admin UI. A `FROM scratch` image that builds is not an image that serves:
#    the SPA is embedded in the binary by the goreleaser build step, and if that
#    step is ever dropped the image still builds and still answers DNS.
#    Fetched unauthenticated because RequireAuth passes non-API paths through
#    on first run so the setup wizard can render.
# ---------------------------------------------------------------------------
step "admin UI serves the embedded SPA"
index="$(curl -fsS --max-time 10 "http://127.0.0.1:$HTTP_PORT/ui/")" \
  || fail "GET /ui/ failed"
grep -q 'id="app"' <<<"$index" || fail "/ui/ did not return the SPA shell"

asset="$(grep -o '/ui/assets/[A-Za-z0-9._-]*\.js' <<<"$index" | head -n1)"
[ -n "$asset" ] || fail "/ui/ has no hashed asset reference — the SPA build is empty"
curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:$HTTP_PORT$asset" \
  || fail "GET $asset failed — only index.html made it into the image"
echo "ok: $asset"

step "root handler responds"
curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:$HTTP_PORT/" || fail "GET / failed"
echo "ok"

# ---------------------------------------------------------------------------
# 7. The seeded /app/cache. A named volume mounted over a directory that does
#    not exist in the image is created root-owned, and uid 100 cannot write to
#    it — the config store would then be unopenable on the compose path.
# ---------------------------------------------------------------------------
step "seeded /app/cache is writable by uid 100"
docker run --rm -v "$VOLUME:/app/cache" alpine:3 \
  sh -c 'test -s /app/cache/smoke.db' \
  || fail "/app/cache/smoke.db was never written — the volume mount is not writable by uid 100"
echo "ok"

echo
echo "SMOKE PASS: $IMAGE"
