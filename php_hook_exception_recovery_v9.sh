#!/usr/bin/env bash
# Research-only PHP 8.4.27 property-hook exception cleanup and iterator recovery in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-hook-exception-v9.XXXXXX)
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
class HookExceptionV9 {
    public int $getCalls = 0;
    public bool $armed = true;
    public int $mode;
    private int $backing = 11;

    public int $value {
        get {
            ++$this->getCalls;
            if ($this->armed) {
                $this->armed = false;
                $this->mutate();
            }
            return $this->backing;
        }
    }

    public function __construct(int $mode) {
        $this->mode = $mode;
        $this->extra_a = 'A';
        $this->extra_b = 'B';
    }

    private function mutate(): void {
        switch ($this->mode) {
            case 0:
                throw new LogicException('expected from getter');
            case 1:
                $this->extra_c = 'C';
                throw new LogicException('expected after append');
            case 2:
                unset($this->extra_a);
                throw new LogicException('expected after unset');
            case 3:
                unset($this->extra_b);
                for ($i = 0; $i < 24; ++$i) {
                    $this->{'created_'.$i} = $i;
                }
                throw new LogicException('expected after hash resize');
            case 4:
                $count = 0;
                foreach ($this as $k => $v) {
                    if (++$count >= 16) break;
                }
                throw new LogicException('expected after nested iterator');
            case 5:
                $dump = var_export($this, true);
                if (!is_string($dump)) throw new RuntimeException('unexpected export output');
                throw new LogicException('expected after nested export');
            case 6:
                $this->extra_c = new class($this) {
                    public function __construct(private object $owner) {}
                    public function __destruct() {
                        unset($this->owner->extra_a);
                        $this->owner->new_from_dtor = true;
                    }
                };
                unset($this->extra_c);
                throw new LogicException('expected after destructor');
            case 7:
                $this->extra_c = 'C';
                // Non-numeric string from a typed hook triggers a TypeError.
                $this->backing = 11;
                throw new TypeError('expected typed failure');
        }
    }
}
$routes = [
    'foreach-value' => static function(object $o): int {
        $n = 0;
        foreach ($o as $name => $value) {
            if (++$n >= 100) break;
        }
        return $n;
    },
    'var_export' => static function(object $o): int {
        return strlen(var_export($o, true));
    },
    'json_encode' => static function(object $o): int {
        return strlen(json_encode($o, JSON_THROW_ON_ERROR));
    },
    'get_object_vars' => static function(object $o): int {
        return count(get_object_vars($o));
    },
    'reflection-get' => static function(object $o): int {
        return (new ReflectionProperty($o, 'value'))->getValue($o);
    },
    'print_r-control' => static function(object $o): int {
        return strlen(print_r($o, true));
    },
];
$m = isset($argv[1]) && is_numeric($argv[1]) ? (int)$argv[1] : -1;
$r = isset($argv[2]) && is_numeric($argv[2]) ? (int)$argv[2] : -1;
$names = array_keys($routes);
if ($m < 0 || $m > 7 || !isset($names[$r])) {
    fwrite(STDERR, "Invalid test selection\n");
    exit(2);
}
$o = new HookExceptionV9($m);
$outer = 'accepted';
try {
    $routes[$names[$r]]($o);
} catch (Throwable $e) {
    $outer = get_class($e);
}
// Some control routes (e.g. print_r) do not invoke a getter.
// Trigger the expected first exception separately, then assess the clean recovery.
if ($o->armed) {
    try { $discard = $o->value; } catch (Throwable $expected) {}
}
$recovery = 'accepted';
$final = -1;
try {
    $final = $o->value;
    $n = 0;
    foreach ($o as $key => $v) {
        if (++$n >= 100) break;
    }
} catch (Throwable $e) {
    $recovery = get_class($e);
}
$flag = ($recovery !== 'accepted' || $final !== 11) ? 'REVIEW' : 'RESULT';
echo "$flag mode=$m route={$names[$r]} outer=$outer recovery=$recovery recovered_value=$final getter_calls={$o->getCalls}\n";

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

echo '=== SMOKE TEST: RE-ENTRANT GETTER EXCEPTION, THEN RECOVERY ==='
if ! timeout 8s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
 "$CLI" -n "$DIR/probe.php" 0 4 > "$DIR/smoke.log" 2>&1; then
 echo 'STOP: harness smoke test failed'
 tail -n 20 "$DIR/smoke.log"
 exit 1
fi
cat "$DIR/smoke.log"
echo '=== GETTER EXCEPTION AND ITERATOR RECOVERY MATRIX ==='
echo 'Modes: 0 throw; 1 append+throw; 2 unset+throw; 3 resize+throw; 4 nested iterator+throw; 5 nested export+throw; 6 destructor+throw; 7 explicit TypeError'
echo 'Routes: 0 foreach; 1 var_export; 2 JSON; 3 get_object_vars; 4 reflection; 5 print_r control'
NORMAL=0
REVIEW=0
ABORT=0
OTHER=0
for I in 0 1 2 3 4 5 6 7; do
  for J in 0 1 2 3 4 5; do
    RC=0
    timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
      "$CLI" -n "$DIR/probe.php" "$I" "$J" > "$DIR/out.log" 2>&1 || RC=$?
    if [ "$RC" -eq 0 ]; then
      NORMAL=$((NORMAL+1))
      if grep -q '^REVIEW ' "$DIR/out.log"; then
        REVIEW=$((REVIEW+1))
      fi
      grep -E '^RESULT |^REVIEW |^Warning:' "$DIR/out.log" | head -n 5 || cat "$DIR/out.log"
    elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
      ABORT=$((ABORT+1))
      echo "ABORT mode=$I route=$J exit=$RC"
      grep -m 2 -E 'Assertion|ERROR: AddressSanitizer|Segmentation fault' "$DIR/out.log" || tail -n 5 "$DIR/out.log"
    else
      OTHER=$((OTHER+1))
      echo "ERROR mode=$I route=$J exit=$RC"
      tail -n 5 "$DIR/out.log"
    fi
  done
done
echo "SUMMARY cases=48 completed=$NORMAL recovery_reviews=$REVIEW abort_or_segfault=$ABORT other_exit=$OTHER"

echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT