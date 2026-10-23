#!/usr/bin/env bash
# Research-only PHP 8.4.27 SPL iterator/access invariants in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-zend-iterator-v4.XXXXXX)
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
$tests = 0;
$reviews = 0;
$rejections = 0;
$baselineChanges = 0;
echo 'PHP=' . PHP_VERSION . "\n";
foreach ($cases as $class) {
    foreach ($operations as $name => $op) {
        $object = new $class();
        $outcome = 'accepted';
        try {
            $op($object);
        } catch (Throwable $e) {
            $outcome = get_class($e);
            $rejections++;
        }
        $state = stateOf($object);
        $mutated = $state !== '[7,["safe"]]';
        $tests++;
        if ($class === PublicBaseline::class && $mutated) {
            $baselineChanges++;
        }
        if ($class !== PublicBaseline::class && $mutated) {
            $reviews++;
            echo "REVIEW class=$class route=$name outcome=$outcome state=$state\n";
        } else {
            echo "OBSERVED class=$class route=$name outcome=$outcome changed=" . ($mutated ? 'yes' : 'no') . "\n";
        }
    }
}

// Same SPL write site called on multiple classes: assess cached access decisions.
function sameSplWrite(object $object): string {
    try {
        $it = new ArrayIterator($object);
        $it['value'] = 99;
        return 'accepted';
    } catch (Throwable $e) {
        return get_class($e);
    }
}
$cacheChecks = 96;
for ($i = 0; $i < $cacheChecks; $i++) {
    $class = $cases[$i % count($cases)];
    $object = new $class();
    $outcome = sameSplWrite($object);
    if ($class !== PublicBaseline::class && stateOf($object) !== '[7,["safe"]]') {
        $reviews++;
        echo "REVIEW cache-cycle=$i class=$class outcome=$outcome state=" . stateOf($object) . "\n";
    }
}
echo "SUMMARY routes=$tests cache_cycles=$cacheChecks exceptions=$rejections baseline_modified=$baselineChanges OTHER_REVIEW=$reviews\n";

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

echo '=== RUN SPL ITERATOR ACCESS CHECKS, NO NETWORK ==='
if timeout 25s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' "$CLI" -n "$DIR/probe.php" > "$DIR/results.txt" 2>&1; then
  cat "$DIR/results.txt"
else
  CODE=$?
  echo "REVIEW: CLI exited with status $CODE"
  tail -n 60 "$DIR/results.txt"
fi
echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT