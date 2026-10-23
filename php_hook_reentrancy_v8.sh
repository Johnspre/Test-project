#!/usr/bin/env bash
# Research-only PHP 8.4.27 property-hook iterator re-entrancy checks in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-hook-reentry-v8.XXXXXX)
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
class ReentrantHookV8 {
    public int $getterCalls = 0;
    public bool $touched = false;
    public int $action = 0;
    private int $stored = 7;

    public int $value {
        get {
            ++$this->getterCalls;
            if (!$this->touched) {
                $this->touched = true;
                $this->mutate();
            }
            return $this->stored;
        }
    }

    public function __construct(int $action) {
        $this->action = $action;
        $this->extra_a = 'A';
        $this->extra_b = 'B';
    }

    private function mutate(): void {
        switch ($this->action) {
            case 0:
                break;
            case 1:
                $this->extra_c = 'C';
                break;
            case 2:
                unset($this->extra_a);
                break;
            case 3:
                unset($this->extra_b);
                $this->extra_c = 'C';
                break;
            case 4:
                for ($i = 0; $i < 24; ++$i) {
                    $this->{'new_'.$i} = $i;
                }
                break;
            case 5:
                unset($this->extra_a, $this->extra_b);
                for ($i = 0; $i < 24; ++$i) {
                    $this->{'added_'.$i} = $i;
                }
                break;
            case 6:
                $nested = var_export($this, true);
                if (!is_string($nested)) {
                    throw new LogicException('var_export unexpectedly failed');
                }
                break;
            case 7:
                $count = 0;
                foreach ($this as $key => $val) {
                    ++$count;
                    if ($count >= 12) break;
                }
                break;
        }
    }
}

$actions = range(0, 7);
$routes = [
    'foreach-by-value' => static function ($o): int {
        $n = 0;
        foreach ($o as $k => $v) {
            if (++$n >= 64) break;
        }
        return $n;
    },
    'var_export' => static function ($o): int {
        $v = var_export($o, true);
        return strlen($v);
    },
    'print_r' => static function ($o): int {
        $v = print_r($o, true);
        return strlen($v);
    },
    'json_encode' => static function ($o): int {
        $v = json_encode($o, JSON_THROW_ON_ERROR);
        return strlen($v);
    },
    'serialize' => static function ($o): int {
        return strlen(serialize($o));
    },
    'get_object_vars' => static function ($o): int {
        return count(get_object_vars($o));
    },
    'array-cast' => static function ($o): int {
        return count((array) $o);
    },
    'reflection-get' => static function ($o): int {
        $v = (new ReflectionProperty($o, 'value'))->getValue($o);
        return (int) $v;
    }
];

$a = isset($argv[1]) && ctype_digit($argv[1]) ? (int) $argv[1] : -1;
$r = isset($argv[2]) && ctype_digit($argv[2]) ? (int) $argv[2] : -1;
$names = array_keys($routes);
if (!isset($actions[$a], $names[$r])) {
    fwrite(STDERR, "Invalid test selection\n");
    exit(2);
}
$obj = new ReentrantHookV8($actions[$a]);
$outcome = 'accepted';
$metric = -1;
try {
    $metric = $routes[$names[$r]]($obj);
} catch (Throwable $e) {
    $outcome = get_class($e);
}
echo "RESULT action=$a route={$names[$r]} outcome=$outcome metric=$metric getter_calls={$obj->getterCalls} touched=" . ($obj->touched ? 'yes' : 'no') . "\n";

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

echo '=== SMOKE TEST: DIRECT REFLECTION GET WITHOUT MUTATION ==='
if ! timeout 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
 "$CLI" -n "$DIR/probe.php" 0 7 > "$DIR/smoke.log" 2>&1; then
 echo 'STOP: harness smoke test failed'
 tail -n 20 "$DIR/smoke.log"
 exit 1
fi
cat "$DIR/smoke.log"
echo '=== HOOKED ITERATOR RE-ENTRANCY: 64 ISOLATED PHP PROCESSES ==='
echo 'Routes: 0 foreach-value, 1 var_export, 2 print_r, 3 json, 4 serialize, 5 get_object_vars, 6 array-cast, 7 reflection-get'
echo 'Actions: 0 no-op, 1 insert, 2 unset, 3 unset+insert, 4 bulk insert, 5 bulk replace, 6 nested export, 7 nested iteration'
NORMAL=0
THROWS=0
ABORT=0
OTHER=0
for I in 0 1 2 3 4 5 6 7; do
 for J in 0 1 2 3 4 5 6 7; do
  RC=0
  timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
    "$CLI" -n "$DIR/probe.php" "$I" "$J" > "$DIR/out.log" 2>&1 || RC=$?
  if [ "$RC" -eq 0 ]; then
    NORMAL=$((NORMAL+1))
    if grep -q 'outcome=[^a]' "$DIR/out.log"; then
       THROWS=$((THROWS+1))
       echo "THROW case=$I/$J $(cat "$DIR/out.log")"
    else
       cat "$DIR/out.log"
    fi
  elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
    ABORT=$((ABORT+1))
    echo "ABORT case=$I/$J exit=$RC"
    grep -m 3 -E 'Assertion|ERROR: AddressSanitizer|runtime error:|Segmentation fault' "$DIR/out.log" || tail -n 4 "$DIR/out.log"
  else
    OTHER=$((OTHER+1))
    echo "OTHER case=$I/$J exit=$RC"
    tail -n 5 "$DIR/out.log"
  fi
 done
done
echo "SUMMARY cases=64 normal=$NORMAL caught_exceptions=$THROWS abort_or_segfault=$ABORT other_exit=$OTHER"

echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT