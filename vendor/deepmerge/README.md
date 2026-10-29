# Local deepmerge security patch

This private development package contains the CommonJS bundle and declarations
from [deepmerge 4.3.1](https://registry.npmjs.org/deepmerge/-/deepmerge-4.3.1.tgz),
including its MIT license. The bundle includes `is-mergeable-object`; it has no
runtime dependencies and needs no build or install script.

The only behavior change rejects `__proto__` by name in both the target-copy and
source-merge loops. This prevents the returned object's prototype from being
replaced, including when the target has no prototype, has a primitive or null
placeholder, or already owns a `__proto__` property. Other merge behavior and
the `merge` / `merge.all` API are retained.

References: [GHSA-GCQX-W48M-W2H4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4)
and the [unmerged upstream fix](https://github.com/TehShrike/deepmerge/pull/274).
No patched upstream version was published as of 2026-10-29.

The root development dependency and `jest-config` override select this local
package. It is excluded from the published library's file list. npm audits do
not inspect vendored code, so `audit:ci` also runs `test:deepmerge`, which checks
Jest's actual dependency resolution, poisoning regressions, and merge behavior.

When upstream publishes a fix, validate the same regression suite before
removing this directory and the root dependency/override. Do not replace this
package with an affected upstream version just to simplify the dependency tree.
