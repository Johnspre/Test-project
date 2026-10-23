#!/usr/bin/env bash
# Research-only PHP 8.4.27 Zend access invariants in an ephemeral Docker snapshot.
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
DIR=$(mktemp -d /tmp/php-zend-access-v2.XXXXXX)
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

class PrivateState {
    public private(set) int $value = 7;
    public private(set) array $items = ['safe'];
    public function legalWrite(): void { $this->value = 8; }
}
class ParentState {
    public protected(set) int $value = 7;
    public protected(set) array $items = ['safe'];
}
class ChildState extends ParentState {
    public function legalWrite(): void { $this->value = 8; }
}
class HookState {
    public private(set) int $value = 7 {
        get => $this->value;
        set => $this->value = $value;
    }
    public private(set) array $items = ['safe'] {
        get => $this->items;
        set => $this->items = $value;
    }
}
class PublicState { public int $value = 7; }
class MagicState {
    public private(set) int $value = 7;
    public function __construct(bool $unset) { if ($unset) unset($this->value); }
    public function __set(string $key, mixed $value): void {}
}

// Mutation attempts from global scope: write access should normally be denied.
$ops = [
 'assign' => static function($o): void {$o->value = 99;},
 'dynamic-assign' => static function($o): void {$key='value'; $o->$key = 99;},
 'compound' => static function($o): void {$o->value += 92;},
 'increment' => static function($o): void {$o->value++;},
 'reference' => static function($o): void {$r = &$o->value; $r = 99;},
 'dynamic-reference' => static function($o): void {$key='value'; $r = &$o->$key; $r = 99;},
 'by-ref-call' => static function($o): void {$f = static function (&$x): void {$x=99;}; $f($o->value);},
 'unset' => static function($o): void {unset($o->value);},
 'array-append' => static function($o): void {$o->items[] = 'changed';},
 'array-index' => static function($o): void {$o->items[0] = 'changed';},
 'array-reference' => static function($o): void {$r = &$o->items; $r[]='changed';},
 'array-pop' => static function($o): void {array_pop($o->items);},
 'array-sort' => static function($o): void {sort($o->items);},
 'array-by-ref-call' => static function($o): void {$f=static function (&$x): void {$x=['changed'];}; $f($o->items);},
 'foreach-object-reference' => static function($o): void {foreach ($o as $k=>&$v) {if($k==='value') $v=99; if($k==='items') $v=['changed'];} unset($v);},
 'foreach-arraycast-reference' => static function($o): void {foreach ((array)$o as $k=>&$v) {if($k==='value') $v=99;} unset($v);},
 'foreach-objectvars-reference' => static function($o): void {foreach (get_object_vars($o) as $k=>&$v) {if($k==='value') $v=99;} unset($v);},
];

$tests=0; $known24280=0; $known24250=0; $review=0;
echo 'PHP='.PHP_VERSION."\n";
foreach ([PrivateState::class, ChildState::class, HookState::class] as $class) {
    foreach ($ops as $name=>$fn) {
        $o = new $class();
        try {$fn($o); $result='accepted';}
        catch (Throwable $e) {$result=get_class($e);}
        $tests++;
        if ($o->value !== 7 || $o->items !== ['safe']) {
            $entry="$class/$name ($result) value={$o->value} items=".json_encode($o->items);
            if ($name==='foreach-object-reference') { $known24280++; echo "KNOWN_24280 $entry\n"; }
            else { $review++; echo "REVIEW $entry\n"; }
        }
    }
}
$private = new PrivateState(); $private->legalWrite();
$child = new ChildState(); $child->legalWrite();
if ($private->value !== 8 || $child->value !== 8) { $review++; echo "REVIEW: legal scoped write failed\n"; }

// The *same instruction* is reused for unrelated class instances.
function sameSiteWrite(object $o): bool {
    try {$o->value = 99; return true;} catch (Throwable) {return false;}
}
for ($i=0;$i<240;$i++) {
    $class = match($i % 4) {0=>PublicState::class,1=>PrivateState::class,2=>ChildState::class,3=>HookState::class};
    $o = new $class();
    $allowed=sameSiteWrite($o);
    $expected=($class===PublicState::class);
    if ($allowed!==$expected || $o->value!==($expected?99:7)) {
        $review++; echo "REVIEW cache-polymorphism iteration=$i class=$class outcome=".($allowed?'accepted':'rejected')." value={$o->value}\n";
    }
}

// Known issue #24250: magic __set() primes an opcode cache entry.
function magicSameSite(MagicState $o): bool {
    try {$o->value=99; return true;} catch (Throwable) {return false;}
}
for ($i=0;$i<20;$i++) {
    magicSameSite(new MagicState(true));
    $o = new MagicState(false);
    $accepted=magicSameSite($o);
    if ($o->value!==7) {
        $known24250++;
        echo "KNOWN_24250 iteration=$i mutated={$o->value} accepted=".($accepted?'yes':'no')."\n";
    }
}
echo "SUMMARY variants=$tests cache_switches=240 magic_cycles=20 known_24280=$known24280 known_24250=$known24250 OTHER_REVIEW=$review\n";
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

echo '=== RUN ACCESS CHECKS, NO NETWORK ==='
if timeout 25s env ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:print_stacktrace=1' "$CLI" -n "$DIR/probe.php" > "$DIR/results.txt" 2>&1; then
  cat "$DIR/results.txt"
else
  CODE=$?
  echo "REVIEW: CLI exited with status $CODE"
  tail -n 60 "$DIR/results.txt"
fi
echo 'NOTE: temporary investigation files disappear when this isolated container exits.'
LABSCRIPT