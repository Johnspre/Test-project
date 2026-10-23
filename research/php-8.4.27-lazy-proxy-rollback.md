# PHP 8.4.27 lazy proxy rollback inconsistency — research note

**Date:** 2026-10-23  
**Research branch:** `Johnspre/Test-project@php-security-lab`  
**Status:** Reproduced, **known upstream bug** (GH-20174), existing upstream fix; do not report as a new vulnerability.

## Summary

A failing `ReflectionClass::newLazyProxy()` factory can leave modifications to the proxy's declared property slots intact. The proxy is still marked as uninitialized, but a subsequent property read may return the partially written value without calling the factory again.

This contradicts the documented rule that a failed lazy-object initializer must revert the object's state. The observed behavior is consistent with [PHP issue #20174](https://github.com/php/php-src/issues/20174) and its existing fix, [commit `4a1cca7`](https://github.com/php/php-src/commit/4a1cca7ddc3deb615aa8e9cc66a9b4c9cf3d8f35), which explicitly adds missing state rollback for lazy proxies.

## Test environment and isolation

- PHP: 8.4.27, isolated source-build CLI.
- Debug and AddressSanitizer research environment; binary rebuilt non-PIE.
- The test ran in an ephemeral Docker snapshot of the **stopped** `php-exif-lab-builder`, with `--network none`, 0.20 CPU, 512 MiB memory, and zero host mounts.
- The original builder and production containers were not used as test targets.
- Test runner: [`php_lazy_failure_recovery_v10.sh`](../php_lazy_failure_recovery_v10.sh).

## Observed results

The matrix had 40 cases across two lazy-object strategies, four factory mutation modes, and five access routes. Results:

```text
SUMMARY cases=40 pass=35 review=5 abort_or_segfault=0 other_exit=0
```

All five discrepancies were for **lazy proxy + mutate declared typed properties before throwing** (`strategy=1 mode=1`), independent of the first access route (read, isset, foreach, clone, serialize).

Representative case:

```text
REVIEW strategy=1 mode=1 route=0
first=LogicException second=accepted
attempts=1 value=11 cache=["temporary"]
lazy_after_fail=1 lazy_after_recovery=1
```

**Expected for the research test:** the factory is called a second time, succeeds, and yields `value=42`, `cache=["done"]`, `attempts=2`, with the object no longer uninitialized.

**Observed:** the second read returned the partially written property values after only one initializer invocation.

A comparable lazy ghost control recovered correctly:

```text
PASS strategy=0 mode=1 route=0
first=LogicException second=accepted
attempts=2 value=42 cache=["done"]
lazy_after_fail=1 lazy_after_recovery=0
```

No crashes, AddressSanitizer errors, or unexpected process exits were reported in this matrix.

## Source inspection and existing fix

The tested version's `Zend/zend_lazy_objects.c`, inside `zend_lazy_object_init_proxy()`, restores `IS_OBJ_LAZY_UNINITIALIZED|IS_OBJ_LAZY_PROXY` when the factory throws but does not restore modified declared property slots.

The [existing upstream commit `4a1cca7`](https://github.com/php/php-src/commit/4a1cca7ddc3deb615aa8e9cc66a9b4c9cf3d8f35) introduces snapshots for declared and dynamic properties and invokes `zend_lazy_object_revert_init()` in the failure path.

At the time of source inspection (2026-10-23):
- [PHP-8.4](https://github.com/php/php-src/blob/PHP-8.4/Zend/zend_lazy_objects.c): old proxy failure path, no equivalent rollback call.
- [PHP-8.5](https://github.com/php/php-src/blob/PHP-8.5/Zend/zend_lazy_objects.c): same old proxy failure path.
- [master](https://github.com/php/php-src/blob/master/Zend/zend_lazy_objects.c): includes the rollback fix.

The bug was already reported upstream as [GH-20174](https://github.com/php/php-src/issues/20174), and [PR #20181](https://github.com/php/php-src/pull/20181) documented the underlying fault. Do not claim original discovery of the bug or the fix.

## Security and disclosure assessment

This is a **reproduced correctness/integrity bug** under a specific usage pattern: a proxy factory modifies its proxy and then throws. It is not evidence of arbitrary-code execution, remote exploitability, or a new CVE. Impact depends on an application's use of lazy proxies and its failure handling.

**Recommended contribution:** ask the PHP maintainers whether the already-existing fix should be backported to supported PHP 8.4/8.5 branches, and if appropriate test the upstream patch against the version-specific test suite. Do not submit a duplicate security disclosure.

## Evidence limitations

This note is based on the supplied PHP 8.4.27 test output, inspected PHP source branches, PHP documentation, and the linked PHP issues and commit. The upstream patch itself was **not** compiled/tested on the user's 8.4.27 lab in this research step; source-branch comparison is not a substitute for a successful backport build and regression run.
