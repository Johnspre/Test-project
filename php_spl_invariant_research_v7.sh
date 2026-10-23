#!/usr/bin/env bash
# Research-only PHP 8.4.27 SPL typed property and hook checks in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-spl-invariants-v7.XXXXXX)
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

class PublicCaseV7 { public int $value = 7; }
class PrivateCaseV7 { public private(set) int $value = 7; }
class ReadonlyCaseV7 {
    public readonly int $value;
    public function __construct() { $this->value = 7; }
}
class HookCaseV7 {
    public int $setCalls = 0;
    public int $value = 7 {
        get => $this->value;
        set {
            $this->setCalls++;
            if ($value !== 7) throw new LogicException('setter rejects mutation');
            $this->value = $value;
        }
    }
}
$classes = [PublicCaseV7::class, PrivateCaseV7::class, ReadonlyCaseV7::class, HookCaseV7::class];
$routes = [
    'direct-int' => static function($o): void { $o->value = 99; },
    'direct-string' => static function($o): void { $o->value = 'BAD'; },
    'ArrayIterator-int' => static function($o): void { $it=new ArrayIterator($o); $it['value']=99; },
    'ArrayIterator-string' => static function($o): void { $it=new ArrayIterator($o); $it['value']='BAD'; },
    'ArrayObject-int' => static function($o): void { $it=new ArrayObject($o); $it['value']=99; },
    'ArrayObject-string' => static function($o): void { $it=new ArrayObject($o); $it['value']='BAD'; },
    'ArrayIterator-unset' => static function($o): void { $it=new ArrayIterator($o); unset($it['value']); },
    'ArrayObject-unset' => static function($o): void { $it=new ArrayObject($o); unset($it['value']); },
];
$c=isset($argv[1]) && is_numeric($argv[1]) ? (int)$argv[1] : -1;
$r=isset($argv[2]) && is_numeric($argv[2]) ? (int)$argv[2] : -1;
$names=array_keys($routes);
if(!isset($classes[$c],$names[$r])) {fwrite(STDERR,"Invalid case\n");exit(2);}
$o=new $classes[$c]();
$outcome='accepted';
try {$routes[$names[$r]]($o);} catch(Throwable $e) {$outcome=get_class($e);}
$rp=new ReflectionProperty($o,'value');
$initialized=$rp->isInitialized($o);
$raw=$initialized ? $rp->getRawValue($o) : null;
$type=$initialized ? get_debug_type($raw) : 'uninitialized';
$value=$initialized ? json_encode($raw,JSON_THROW_ON_ERROR) : '<unset>';
$calls=$o instanceof HookCaseV7 ? $o->setCalls : -1;
$changed=!$initialized || $raw !== 7;
$typeBypass=$initialized && $type !== 'int';
$forbiddenChange=$changed && ($o instanceof PrivateCaseV7 || $o instanceof ReadonlyCaseV7);
$hookSkipped=$changed && $o instanceof HookCaseV7 && $calls===0;
$flag=$typeBypass || $forbiddenChange || $hookSkipped ? 'REVIEW' : 'RESULT';
echo "$flag class={$classes[$c]} route={$names[$r]} outcome=$outcome type=$type value=$value hooks=$calls";
echo ' TYPE_BYPASS='.($typeBypass?'YES':'no');
echo ' GUARD_BYPASS='.($forbiddenChange?'YES':'no');
echo ' HOOK_BYPASS='.($hookSkipped?'YES':'no')."\n";

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

echo '=== SMOKE TEST ==='
if ! timeout 10s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
  "$CLI" -n "$DIR/probe.php" 0 0 > "$DIR/smoke.log" 2>&1; then
  echo 'STOP: smoke test failed'
  tail -n 15 "$DIR/smoke.log"
  exit 1
fi
cat "$DIR/smoke.log"
echo '=== ACCESS, TYPE AND HOOK INVARIANT CHECKS ==='
NORMAL=0; REVIEW=0; ABORT=0; FAIL=0
for I in 0 1 2 3; do
  for J in 0 1 2 3 4 5 6 7; do
    RC=0
    timeout -s TERM -k 1 5s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' \
      "$CLI" -n "$DIR/probe.php" "$I" "$J" > "$DIR/output.log" 2>&1 || RC=$?
    if [ "$RC" -eq 0 ]; then
      NORMAL=$((NORMAL+1))
      if grep -q '^REVIEW ' "$DIR/output.log"; then REVIEW=$((REVIEW+1)); fi
      cat "$DIR/output.log"
    elif [ "$RC" -eq 134 ] || [ "$RC" -eq 139 ]; then
      ABORT=$((ABORT+1))
      echo "ABORT class=$I route=$J exit=$RC"
      grep -m 1 -E 'Assertion|ERROR: AddressSanitizer' "$DIR/output.log" || tail -n 3 "$DIR/output.log"
    else
      FAIL=$((FAIL+1))
      echo "ERROR class=$I route=$J exit=$RC"
      tail -n 3 "$DIR/output.log"
    fi
  done
done
echo "SUMMARY cases=32 normal=$NORMAL review=$REVIEW aborted=$ABORT other_errors=$FAIL"

echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT