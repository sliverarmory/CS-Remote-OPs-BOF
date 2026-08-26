# Release safety and authorization

The release workflow is operable with the repository's existing
`MINISIGN_PRIVATE_KEY` secret. Creating and pushing a version tag is the explicit
release authorization: the workflow does not run for branch pushes and does not
create or modify repository settings.

## Current inventory invariants

- `armory-package-inventory.txt` is the canonical, sorted inventory of 51
  packages. A release must contain exactly 51 archives and 51 signatures.
- `armory-package-executors.txt` is the canonical per-package execution policy.
  Every manifest must explicitly select either `reflektor` or `coff-loader`,
  and every Reflektor-routed command must retain `depends_on: coff-loader` for
  old-client and old-implant compatibility. Both x64 and x86 packaged objects
  must pass the Reflektor load/relocation/import check before a package can be
  routed to Reflektor.
- The currently published, signed Armory index contains 47 sibling entries for
  this repository, all using one package public key. Every one of those 47 names
  must remain in the canonical inventory.
- `remote-ask-mfa`, `remote-disableuser`, `remote-get-azure-token`, and
  `remote-shutdown` are canonical packages but are not currently indexed. Adding
  them to Armory is a separate index migration and is not part of this package
  repair.
- The value 47 is a current signed-index invariant, not a permanent catalog
  constant. An authorized index migration must publish and verify a new signed
  index first, then update the validation script and this document together.
- Release `v0.1.3` is immutable history. The next package release is a higher
  version and must never replace or move `v0.1.3`.

`remote-lastpass` is restored as install- and argument-ABI-safe, but its custom
`LASTPASS>>` binary callback stream still requires the Cobalt Strike CNA/Python
postprocessor. Sliver does not yet render that stream into readable LastPass
results, so a no-crash invocation is not proof of full operator functionality.

## Required release inputs

1. The repository secret `MINISIGN_PRIVATE_KEY` must contain the existing package
   private key pinned by the signed Armory index. The workflow accepts either raw
   multiline contents or the historical form containing literal `\n` escapes,
   and uses the key's existing empty passphrase. Signing uses the checksum-pinned
   `aead/minisign` v0.2.0 binary that produced earlier package releases; current
   Minisign independently verifies every result. The workflow reconstructs the
   public key before signing and fails unless it exactly matches the key in the
   verified signed index. Do not generate or substitute a new key.
2. The release tag must be a GitHub-verified signed annotated tag whose embedded
   tag name exactly matches the pushed ref and whose object points directly to a
   commit. The peeled commit must be an ancestor of the repository's current
   default branch. The workflow re-resolves that exact tag immediately before
   publication and fails if it moved.
3. The version must use `vMAJOR.MINOR.PATCH` with no leading zeroes and be
   numerically higher than every published stable release. The immutable
   published `v0.1.3` baseline must remain present.

The repository currently has no protected release environment, tag ruleset, or
protected default branch. Those controls and immutable releases remain strongly
recommended administrative hardening, but are not workflow prerequisites for
this repair release. The workflow compensates within its available authority by
using a read-only token until the publish job, full-SHA action pins,
repository-wide release concurrency, signed-tag and branch-ancestry checks,
exact-ID draft operations, and repeated remote verification. It never creates or
changes repository settings.

## Release flow

The secretless build freezes one verified signed Armory index, public-key
metadata, canonical inventory, and source commit into a same-run
`release-metadata` artifact. The reusable workflow carries the immutable Actions
artifact ID and service SHA-256 to every consumer. Release-ready, sign, and
publish bind downloads to that numeric ID, verify the service digest, then
reverify the internal checksums and Minisign signature. They do not fetch a
different latest index between those stages. Immediately before undrafting, the
publish job downloads the then-current latest index and requires it to be
byte-identical to the carried copy.

Publication uses repository-wide concurrency. Before mutation, the write-scoped
job enumerates all same-tag releases. It classifies the complete set first and
deletes only unpublished drafts carrying this workflow's exact repository, tag,
peeled-commit, run, author, and managed marker; any published, manual, unmarked, or
mismatched entry stops the run without deletion. Newly created drafts include the
same unique run marker. Assets are uploaded and downloaded through the captured
release/asset IDs rather than tag lookup, and the cleanup trap uses the exact
numeric ID or one unique exact run marker after an ambiguous API response. Legacy
unmarked orphan drafts are never deleted automatically.

The workflow verifies all 102 remote asset names, IDs, bytes, signatures, and
trusted manifests. Immediately before undrafting it again requires that this is
the sole same-tag draft, no same-tag published release exists, no higher stable
release has appeared, the exact tag and default-branch ancestry still hold, and
the signed index remains unchanged.

Release versions use `vMAJOR.MINOR.PATCH` with no leading zeroes and must be
numerically higher than the highest published stable release. The immutable
published `v0.1.3` baseline must remain present.

Use a Git signing identity that GitHub marks as verified to create an annotated
tag whose signed embedded tag name exactly matches the pushed ref. Create it on a
commit already contained in the default branch, verify it locally, and push only
that new tag:

```console
git switch main
git pull --ff-only origin main
git tag -s v0.1.5 -m 'CS-Remote-OPs-BOF v0.1.5'
git verify-tag v0.1.5
git push origin refs/tags/v0.1.5
```

Do not move, reuse, or force-push an existing tag.
