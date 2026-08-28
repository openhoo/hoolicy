# Recovery

## Bad pack release

Keep current lock and vendor directory. Run `hoolicy pack update <name>` without `--apply` against last known-good digest, review rule/severity/parameter/control changes, then apply and run `validate`, pack fixtures, and full `check`. Never edit a digest to fit local bytes.

## Compromised publisher identity

Remove identity or key from `.hoolicy/trust.yaml` first. Do not acquire new packs. Preserve affected lock, catalog lock, OCI digest, signature bundle, and evidence bundle for investigation. Rotate key or constrain replacement identity plus issuer, republish from reviewed source under a new digest, then update explicitly. Registry tag movement does not repair already trusted content.

## Corrupt baseline

Move the baseline aside for forensic comparison; a missing baseline exposes all findings as new and is safer than a permissive repair. Run a full check, use `hoolicy baseline create` to preview a fresh exact set, review every entry and policy digest, then apply. Never delete stale entries during `check`.

## Failed fix application

Hoolicy stages hash-bound edits, revalidates path components and original bytes immediately before replacement, and rolls back earlier writes when a later write fails. Inspect working-tree status and the reported target. Do not rerun with force. A process crash between atomic renames may leave a `.hoolicy-backup-*` file beside the target. Compare that exact file with the target and version control; restore or remove only the individually reviewed path. Then rerun `hoolicy fix` to create a new plan against current hashes, review, and apply.

## Invalid or stale external evidence

Do not relax digest, subject, freshness, or threshold policy to turn CI green. Regenerate the specialist artifact for the exact subject, review scanner status independently, update its pinned SHA-256 in `.hoolicy/evidence.yaml`, then recreate and verify Hoolicy evidence.
