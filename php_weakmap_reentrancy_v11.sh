#!/usr/bin/env bash
# Research-only PHP 8.4.27 WeakMap iterator and destructor re-entrancy investigation in an ephemeral Docker snapshot.
# Never start/modify the original builder or any production container.
set -euo pipefail
LAB=php-exif-lab-builder
fail() { echo "STOP: $*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'Docker unavailable.'
docker inspect --type container "$LAB" >/dev/null 2>&1 || fail 'Research builder not found.'

# Read-only checks: the original research builder must be inactive and unmounted.
RUNNING=$(docker inspect -f '{{.State.Running}}' "$LAB")
PRIV=$(docker inspect -f '{{.HostConfig.Privileged}}' "$LAB")
MOUNTS=$(docker inspect -f '{{len .Mounts}}' "$LAB")
PIDMODE=$(docker inspect -f '{{.HostConfig.PidMode}}' "$LAB")
[[ "$RUNNING" == false ]] || fail 'Research builder must be stopped.'
[[ "$PRIV" == false && "$MOUNTS" == 0 && -z "$PIDMODE" ]] || fail 'Unexpected builder privileges/mounts/PID namespace.'

# A stopped builder's writable layer may contain compiled PHP not present in its base image.
# Check Docker's disk filesystem before committing that layer into a local, short-lived image.
RW=$(docker inspect --size -f '{{.SizeRw}}' "$LAB")
[[ "$RW" =~ ^[0-9]+$ ]] || fail 'Cannot determine builder writable layer size.'
ROOT=$(docker info --format '{{.DockerRootDir}}')
[[ -d "$ROOT" ]] || fail 'Cannot read Docker storage directory for disk guard.'
FREE_KB=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
[[ "$FREE_KB" =~ ^[0-9]+$ ]] || fail 'Cannot determine free space on Docker filesystem.'
# Require >= 3 GiB spare beyond 2x the builder writable layer's size.
MIN_FREE=$(( 3*1024*1024*1024 + 2*RW ))
(( FREE_KB*1024 >= MIN_FREE )) || fail "Not enough free disk for safe snapshot: need $((MIN_FREE/1024/1024)) MiB, have $((FREE_KB/1024)) MiB. No changes made."
(( RW <= 3*1024*1024*1024 )) || fail 'Builder writable layer exceeds 3 GiB safe snapshot threshold.'

echo "Preflight PASS: builder stopped; layer=$((RW/1024/1024)) MiB; available=$((FREE_KB/1024)) MiB."
SNAP=''
cleanup() {
  if [[ -n "$SNAP" ]]; then
    docker image rm "$SNAP" >/dev/null 2>&1 || echo "WARNING: remove temporary research image manually: $SNAP" >&2
  fi
}
trap cleanup EXIT

echo '=== Create local ephemeral snapshot of the STOPPED research builder ==='
SNAP=$(docker commit --pause=false "$LAB") || fail 'Could not snapshot research builder.'
[[ "$SNAP" == sha256:* ]] || fail 'Unexpected Docker image ID.'
echo '=== Run isolated research clone; original builder remains stopped ==='
docker run --pull never --rm -i \
  --network none --cpus 0.20 --memory 512m --memory-swap 512m \
  --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --entrypoint /bin/sh "$SNAP" -s <<'LABSCRIPT'
set -eu
ulimit -c 0
cd /opt/php-lab/php-8.4.27
CLI=sapi/cli/php
DIR=$(mktemp -d /tmp/php-weakmap-reentry-v11.XXXXXX)
BACKUP=$(mktemp /tmp/php-cli-backup.XXXXXX)
test -f "$CLI" || { echo 'Missing research PHP CLI'; exit 1; }
cp -p "$CLI" "$BACKUP"
cleanup() {
  cp -p "$BACKUP" "$CLI"
  rm -f "$BACKUP"
  echo 'Original research PHP CLI restored.'
}
trap cleanup EXIT

echo '=== PASSIVE SOURCE CHECK ==='
grep -n 'zend_asymmetric_property_has_set_access' Zend/zend_object_handlers.c | head -n 12 || true
grep -nE 'ZEND_FE_(RESET|FETCH)_RW' Zend/zend_vm_def.h | head -n 12 || true

cat > "$DIR/probe.php" <<'PHP'
<?php
declare(strict_types=1);
error_reporting(E_ALL);

final class TestContextV11 {
    public WeakMap $map;
    public array $keys = [];
    public array $keep = [];
    public int $events = 0;
    public bool $didAction = false;
    public function __construct() {
        $this->map = new WeakMap;
        for ($i = 0; $i < 5; $i++) {
            $key = new stdClass;
            $this->keys[] = $key;
            $this->map[$key] = $i;
        }
    }
    public function addEntries(): void {
        for ($i = 0; $i < 24; $i++) {
            $key = new stdClass;
            $this->keep[] = $key;
            $this->map[$key] = $i;
        }
    }
    public function action(int $mode): void {
        if ($this->didAction) return;
        $this->didAction = true;
        switch ($mode) {
            case 0: break;
            case 1: unset($this->map[$this->keys[0]]); break;
            case 2: unset($this->keys[2]); break;
            case 3: $this->addEntries(); break;
            case 4: case 5: case 6: case 7:
                $this->map[$this->keys[0]] = new WatchedV11($this, $mode);
                $this->map[$this->keys[0]] = 'replacement';
                break;
        }
    }
}
final class WatchedV11 {
    private WeakReference $owner;
    public function __construct(TestContextV11 $owner, private int $mode) {
        $this->owner = WeakReference::create($owner);
    }
    public function __destruct() {
        $ctx = $this->owner->get();
        if (!$ctx) return;
        $ctx->events++;
        switch ($this->mode) {
            case 4: unset($ctx->map[$ctx->keys[3]]); break;
            case 5: $ctx->addEntries(); break;
            case 6: gc_collect_cycles(); break;
            case 7:
                $n = 0;
                foreach ($ctx->map as $key => $value) {
                    if (++$n > 12) break;
                }
                break;
        }
    }
}
$mode = isset($argv[1]) && is_numeric($argv[1]) ? (int)$argv[1] : -1;
$route = isset($argv[2]) && is_numeric($argv[2]) ? (int)$argv[2] : -1;
if ($mode < 0 || $mode > 7 || $route < 0 || $route > 4) {
    fwrite(STDERR, "Invalid test selection\n");
    exit(2);
}
$ctx = new TestContextV11;
$count = 0;
$result = 'accepted';
try {
    switch ($route) {
        case 0:
            foreach ($ctx->map as $key => $value) {
                ++$count;
                $ctx->action($mode);
                if ($count >= 64) break;
            }
            break;
        case 1:
            foreach ($ctx->map as $key => &$value) {
                ++$count;
                $ctx->action($mode);
                if ($count >= 64) break;
            }
            unset($value);
            break;
        case 2:
            $copy = clone $ctx->map;
            foreach ($copy as $key => $value) {
                ++$count;
                $ctx->action($mode);
                if ($count >= 64) break;
            }
            break;
        case 3:
            foreach ($ctx->map as $key => $value) {
                ++$count;
                $ctx->action($mode);
                $inner = 0;
                foreach ($ctx->map as $innerKey => $innerValue) {
                    if (++$inner >= 12) break;
                }
                if ($count >= 64) break;
            }
            break;
        case 4:
            $before = $ctx->map[$ctx->keys[0]];
            unset($before);
            $ctx->action($mode);
            foreach ($ctx->map as $key => $value) {
                if (++$count >= 64) break;
            }
            break;
    }
} catch (Throwable $e) {
    $result = get_class($e);
}
echo "RESULT mode=$mode route=$route outcome=$result counted=$count map_count=".count($ctx->map)." destructor_events={$ctx->events}\n";

PHP

echo '=== REBUILD RESEARCH CLI AS NON-PIE (BACKUP PRESERVED) ==='
rm "$CLI"
if ! timeout 120s make -j1 LDFLAGS='-no-pie' "$CLI" > "$DIR/build.log" 2>&1; then
  echo 'NON-PIE build failed or timed out. Last build output:'
  tail -n 25 "$DIR/build.log"
  exit 1
fi
readelf -h "$CLI" | grep 'Type:'
readelf -h "$CLI" | grep -q 'Type:.*EXEC' || { echo 'STOP: build still PIE.'; exit 1; }
if ! timeout 10s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' "$CLI" -n -r 'echo PHP_VERSION;' | grep -qx '8.4.27'; then
  echo 'STOP: unexpected research PHP version.'; exit 1
fi

echo '=== SMOKE TEST: PLAIN WEAKMAP ITERATION ==='
if ! timeout 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
 "$CLI" -n "$DIR/probe.php" 0 0 > "$DIR/smoke.log" 2>&1; then
  echo 'STOP: PHP research harness smoke test failed'
  tail -n 25 "$DIR/smoke.log"
  exit 1
fi
cat "$DIR/smoke.log"
if ! grep -q '^RESULT mode=0 route=0 outcome=accepted counted=5 map_count=5 destructor_events=0$' "$DIR/smoke.log"; then
  echo 'STOP: WeakMap baseline did not match the expected control'
  exit 1
fi
echo '=== WEAKMAP ITERATION / DESTRUCTOR RE-ENTRANCY MATRIX ==='
echo 'Modes: 0 control, 1 unset current, 2 release another key, 3 grow table, 4 dtor unsets key, 5 dtor grows table, 6 dtor runs GC, 7 dtor iterates map'
echo 'Routes: 0 foreach-value, 1 foreach-reference, 2 clone-map, 3 nested-foreach, 4 direct-read-then-foreach'
COMPLETED=0
ABORT=0
ERROR=0
for I in 0 1 2 3 4 5 6 7; do
 for J in 0 1 2 3 4; do
  RC=0
  timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
    "$CLI" -n "$DIR/probe.php" "$I" "$J" > "$DIR/out.log" 2>&1 || RC=$?
  if [ "$RC" -eq 0 ]; then
    COMPLETED=$((COMPLETED+1))
    cat "$DIR/out.log"
  elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
    ABORT=$((ABORT+1))
    echo "ABORT mode=$I route=$J exit=$RC"
    grep -m 2 -E 'Assertion|ERROR: AddressSanitizer|Segmentation fault' "$DIR/out.log" || tail -n 6 "$DIR/out.log"
  else
    ERROR=$((ERROR+1))
    echo "ERROR mode=$I route=$J exit=$RC"
    tail -n 6 "$DIR/out.log"
  fi
 done
done
echo "SUMMARY cases=40 completed=$COMPLETED abort_or_segfault=$ABORT unexpected_exit=$ERROR"

echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT