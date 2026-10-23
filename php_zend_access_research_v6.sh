#!/usr/bin/env bash
# Research-only PHP 8.4.27 extension-free SPL iterator crash triage in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-zend-iterator-v6.XXXXXX)
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

class PublicBaseline {
    public int $value = 7;
    public array $items = ['safe'];
}
class PrivateSetCase {
    public private(set) int $value = 7;
    public private(set) array $items = ['safe'];
}
class ProtectedSetCase {
    public protected(set) int $value = 7;
    public protected(set) array $items = ['safe'];
}
class HookedCase {
    public private(set) int $value = 7 {
        get => $this->value;
        set => $this->value = $value;
    }
    public private(set) array $items = ['safe'] {
        get => $this->items;
        set => $this->items = $value;
    }
}
class ReadonlyCase {
    public readonly int $value;
    public readonly array $items;
    public function __construct() {
        $this->value = 7;
        $this->items = ['safe'];
    }
}

function stateOf(object $object): string {
    $v = new ReflectionProperty($object, 'value');
    $a = new ReflectionProperty($object, 'items');
    $value = $v->isInitialized($object) ? $object->value : '@uninitialized';
    $items = $a->isInitialized($object) ? $object->items : '@uninitialized';
    return json_encode([$value, $items], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

$operations = [
    'ArrayIterator-foreach-ref' => static function(object $o): void {
        $it = new ArrayIterator($o);
        foreach ($it as $k => &$v) {
            if ($k === 'value') $v = 99;
            if ($k === 'items') $v = ['changed'];
        }
        unset($v);
    },
    'ArrayObject-iterator-foreach-ref' => static function(object $o): void {
        $it = (new ArrayObject($o))->getIterator();
        foreach ($it as $k => &$v) {
            if ($k === 'value') $v = 99;
            if ($k === 'items') $v = ['changed'];
        }
        unset($v);
    },
    'IteratorIterator-foreach-ref' => static function(object $o): void {
        $it = new IteratorIterator(new ArrayIterator($o));
        foreach ($it as $k => &$v) {
            if ($k === 'value') $v = 99;
            if ($k === 'items') $v = ['changed'];
        }
        unset($v);
    },
    'ArrayIterator-offsetSet' => static function(object $o): void {
        $it = new ArrayIterator($o);
        $it['value'] = 99;
        $it['items'] = ['changed'];
    },
    'ArrayObject-offsetSet' => static function(object $o): void {
        $it = new ArrayObject($o);
        $it['value'] = 99;
        $it['items'] = ['changed'];
    },
    'ArrayIterator-offsetUnset' => static function(object $o): void {
        $it = new ArrayIterator($o);
        unset($it['value'], $it['items']);
    },
    'ArrayObject-offsetUnset' => static function(object $o): void {
        $it = new ArrayObject($o);
        unset($it['value'], $it['items']);
    },
    'ArrayIterator-foreach-byvalue' => static function(object $o): void {
        $it = new ArrayIterator($o);
        foreach ($it as $k => $v) {
            if ($k === 'value') $v = 99;
        }
    },
    'copied-objectvars-foreach-ref' => static function(object $o): void {
        $it = new ArrayIterator(get_object_vars($o));
        foreach ($it as $k => &$v) {
            if ($k === 'value') $v = 99;
        }
        unset($v);
    },
    'copied-arraycast-foreach-ref' => static function(object $o): void {
        $it = new ArrayIterator((array) $o);
        foreach ($it as $k => &$v) {
            if ($k === 'value') $v = 99;
        }
        unset($v);
    },
];

$cases = [
    PublicBaseline::class,
    PrivateSetCase::class,
    ProtectedSetCase::class,
    HookedCase::class,
    ReadonlyCase::class,
];
$mode = $argv[1] ?? '';
if ($mode === 'case') {
    $classId = isset($argv[2]) && is_numeric($argv[2]) ? (int)$argv[2] : -1;
    $routeId = isset($argv[3]) && is_numeric($argv[3]) ? (int)$argv[3] : -1;
    $routeNames = array_keys($operations);
    if ($classId === false || $routeId === false ||
        !isset($cases[$classId], $routeNames[$routeId])) {
        fwrite(STDERR, "Invalid test selection\n");
        exit(2);
    }
    $class = $cases[$classId];
    $route = $routeNames[$routeId];
    $object = new $class();
    $outcome = 'accepted';
    try {
        $operations[$route]($object);
    } catch (Throwable $e) {
        $outcome = get_class($e);
    }
    $state = stateOf($object);
    $mutated = $state !== '[7,["safe"]]';
    $prefix = ($class !== PublicBaseline::class && $mutated) ? 'REVIEW' : 'RESULT';
    echo "$prefix class=$class route=$route outcome=$outcome changed=" .
        ($mutated ? 'yes' : 'no') . " state=$state\n";
    exit;
}
if ($mode === 'cache') {
    function sameSplWrite(object $object): string {
        try {
            $it = new ArrayIterator($object);
            $it['value'] = 99;
            return 'accepted';
        } catch (Throwable $e) {
            return get_class($e);
        }
    }
    $review = 0;
    for ($i = 0; $i < 96; $i++) {
        $class = $cases[$i % count($cases)];
        $object = new $class();
        $outcome = sameSplWrite($object);
        if ($class !== PublicBaseline::class && stateOf($object) !== '[7,["safe"]]') {
            $review++;
            echo "CACHE_REVIEW i=$i class=$class outcome=$outcome state=" . stateOf($object) . "\n";
        }
    }
    echo "CACHE_SUMMARY cycles=96 reviews=$review\n";
    exit;
}
fwrite(STDERR, "Usage: php probe.php case CLASS_INDEX ROUTE_INDEX | cache\n");
exit(2);
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

echo '=== SMOKE TEST: FAIL FAST IF A REQUIRED PHP FUNCTION IS MISSING ==='
if ! timeout 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
  "$CLI" -n "$DIR/probe.php" case 0 9 > "$DIR/smoke.log" 2>&1; then
  echo 'STOP: independent-process PHP smoke test failed:'
  tail -n 20 "$DIR/smoke.log"
  exit 1
fi
cat "$DIR/smoke.log"

echo '=== ISOLATED PHP-PROCESS CASE MATRIX (EACH TEST INDEPENDENT) ==='
echo 'Class 0=public 1=private(set) 2=protected(set) 3=hooks 4=readonly'
echo 'Routes: 0=ArrayIterator-ref, 1=ArrayObject-iterator-ref, 2=IteratorIterator-ref, 3=ArrayIterator-offsetSet, 4=ArrayObject-offsetSet, 5=ArrayIterator-offsetUnset, 6=ArrayObject-offsetUnset, 7=ArrayIterator-byvalue, 8=copied-objectvars-ref, 9=copied-arraycast-ref'
PASSED=0
REVIEWS=0
ABORTED=0
FAILED=0
TIMEOUTS=0
for I in 0 1 2 3 4; do
  for J in 0 1 2 3 4 5 6 7 8 9; do
    RC=0
    timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
      "$CLI" -n "$DIR/probe.php" case "$I" "$J" > "$DIR/result.log" 2>&1 || RC=$?
    if [ "$RC" -eq 0 ]; then
      PASSED=$((PASSED+1))
      if grep -q '^REVIEW ' "$DIR/result.log"; then
        REVIEWS=$((REVIEWS+1))
        echo "CASE class=$I route=$J RESULT=REVIEW"
        grep '^REVIEW ' "$DIR/result.log" || true
      fi
    elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
      ABORTED=$((ABORTED+1))
      echo "CASE class=$I route=$J RESULT=ABORT exit=$RC"
      grep -m 2 -E 'Assertion|ERROR: AddressSanitizer|runtime error:|Segmentation fault' "$DIR/result.log" || tail -n 3 "$DIR/result.log"
    elif [ "$RC" -eq 124 ] || [ "$RC" -eq 137 ]; then
      TIMEOUTS=$((TIMEOUTS+1))
      echo "CASE class=$I route=$J RESULT=TIMEOUT_OR_KILL exit=$RC"
    else
      FAILED=$((FAILED+1))
      echo "CASE class=$I route=$J RESULT=ERROR exit=$RC"
      tail -n 4 "$DIR/result.log"
    fi
  done
done
echo "=== ISOLATED RUNTIME CACHE PROBE ==="
RC=0
timeout -s TERM -k 1 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
  "$CLI" -n "$DIR/probe.php" cache > "$DIR/cache.log" 2>&1 || RC=$?
echo "CACHE_EXIT=$RC"
grep -E '^CACHE_REVIEW|^CACHE_SUMMARY|Assertion|ERROR: AddressSanitizer' "$DIR/cache.log" | head -n 30 || true
echo "SUMMARY cases=50 normal_exits=$PASSED mutating_access_reviews=$REVIEWS assertion_or_segfault=$ABORTED unexpected_exit=$FAILED timeout_or_kill=$TIMEOUTS cache_exit=$RC"
echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT