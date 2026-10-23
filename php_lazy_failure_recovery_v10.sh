#!/usr/bin/env bash
# Research-only PHP 8.4.27 lazy ghost/proxy exception-recovery comparison in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-lazy-recovery-v10.XXXXXX)
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

#[AllowDynamicProperties]
class LazyTargetV10 {
    public int $value = 7;
    public array $cache = ['safe'];
    public string $stage = 'base';
    public ?object $payload = null;
}

$strategy = isset($argv[1]) && is_numeric($argv[1]) ? (int) $argv[1] : -1;
$mode = isset($argv[2]) && is_numeric($argv[2]) ? (int) $argv[2] : -1;
$route = isset($argv[3]) && is_numeric($argv[3]) ? (int) $argv[3] : -1;
if ($strategy < 0 || $strategy > 1 || $mode < 0 || $mode > 3 ||
    $route < 0 || $route > 4) {
    fwrite(STDERR, "Invalid test selection\n");
    exit(2);
}

$attempts = 0;
$initializer = static function (LazyTargetV10 $target) use (&$attempts, $mode, $strategy) {
    ++$attempts;
    if ($attempts === 1) {
        switch ($mode) {
            case 0:
                break;
            case 1:
                $target->value = 11;
                $target->cache[] = 'temporary';
                $target->stage = 'partial';
                break;
            case 2:
                $target->created = ['temporary'];
                $target->more = 4;
                unset($target->created);
                break;
            case 3:
                $target->payload = $target;
                break;
        }
        throw new LogicException('intentional first initialization failure');
    }
    if ($strategy === 0) {
        $target->value = 42;
        $target->cache = ['done'];
        $target->stage = 'complete';
        return;
    }
    $real = new LazyTargetV10;
    $real->value = 42;
    $real->cache = ['done'];
    $real->stage = 'complete';
    return $real;
};

$reflection = new ReflectionClass(LazyTargetV10::class);
$lazy = $strategy === 0
    ? $reflection->newLazyGhost($initializer)
    : $reflection->newLazyProxy($initializer);
$first = 'accepted';
try {
    switch ($route) {
        case 0: $ignored = $lazy->value; break;
        case 1: $ignored = isset($lazy->value); break;
        case 2: foreach ($lazy as $key => $value) { break; } break;
        case 3: $ignored = clone $lazy; break;
        case 4: $ignored = serialize($lazy); break;
    }
} catch (Throwable $error) {
    $first = get_class($error);
}
if ($attempts === 0) {
    try {
        $ignored = $lazy->value;
    } catch (Throwable $error) {
        $first = get_class($error);
    }
}
$uninitAfterFailure = $reflection->isUninitializedLazyObject($lazy);
$second = 'accepted';
$finalValue = 'unset';
$finalCache = 'unset';
try {
    $finalValue = $lazy->value;
    $finalCache = $lazy->cache;
} catch (Throwable $error) {
    $second = get_class($error);
}
$uninitAfterRecovery = $reflection->isUninitializedLazyObject($lazy);
$pass = $attempts === 2
    && $first === LogicException::class
    && $second === 'accepted'
    && $finalValue === 42
    && $finalCache === ['done']
    && $uninitAfterFailure
    && !$uninitAfterRecovery;
echo ($pass ? 'PASS' : 'REVIEW')
    . " strategy=$strategy mode=$mode route=$route first=$first second=$second"
    . " attempts=$attempts value=" . json_encode($finalValue)
    . ' cache=' . json_encode($finalCache)
    . ' lazy_after_fail=' . (int) $uninitAfterFailure
    . ' lazy_after_recovery=' . (int) $uninitAfterRecovery . "\n";

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

echo '=== SMOKE TEST: LAZY GHOST THROWS ONCE AND RECOVERS ==='
if ! timeout 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
  "$CLI" -n "$DIR/probe.php" 0 0 0 > "$DIR/smoke.log" 2>&1; then
  echo 'STOP: PHP harness smoke test failed'
  tail -n 15 "$DIR/smoke.log"
  exit 1
fi
cat "$DIR/smoke.log"
if ! grep -q '^PASS ' "$DIR/smoke.log"; then
  echo 'STOP: ghost baseline did not recover correctly'
  exit 1
fi

echo '=== LAZY GHOST VS LAZY PROXY FAILURE-RECOVERY MATRIX ==='
echo 'Strategy 0=ghost; 1=proxy'
echo 'Mode 0=throw-no-mutation; 1=modify-typed-props+throw; 2=dynamic-props+throw; 3=self-reference+throw'
echo 'Route 0=read; 1=isset; 2=foreach; 3=clone; 4=serialize'
PASS=0
REVIEW=0
ABORT=0
OTHER=0
for S in 0 1; do
  for M in 0 1 2 3; do
    for R in 0 1 2 3 4; do
      RC=0
      timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
        "$CLI" -n "$DIR/probe.php" "$S" "$M" "$R" > "$DIR/out.log" 2>&1 || RC=$?
      if [ "$RC" -eq 0 ]; then
        if grep -q '^PASS ' "$DIR/out.log"; then
          PASS=$((PASS+1))
          if [ "$R" -eq 0 ]; then cat "$DIR/out.log"; fi
        else
          REVIEW=$((REVIEW+1))
          cat "$DIR/out.log"
        fi
      elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
        ABORT=$((ABORT+1))
        echo "ABORT strategy=$S mode=$M route=$R exit=$RC"
        grep -m 2 -E 'Assertion|ERROR: AddressSanitizer|Segmentation fault' "$DIR/out.log" || tail -n 5 "$DIR/out.log"
      else
        OTHER=$((OTHER+1))
        echo "OTHER strategy=$S mode=$M route=$R exit=$RC"
        tail -n 5 "$DIR/out.log"
      fi
    done
  done
done
echo "SUMMARY cases=40 pass=$PASS review=$REVIEW abort_or_segfault=$ABORT other_exit=$OTHER"

echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT