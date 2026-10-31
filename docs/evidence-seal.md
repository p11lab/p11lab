# Evidence envelope seal

A successful local validation produces two related JSON envelopes, not
one. `validation-body.json` is sealed *inside* the evidence package; the
familiar `validation.json` stays *outside* as the envelope that carries
the two seal records binding it to the package.

## The two envelopes

The produce step composes the body first: every result field except the
`package` seal record (29 keys). That body is written to the output tree
as `validation-body.json`, sealed and packaged together with the rest of
the fixed evidence roster, and only then is the envelope written. The
envelope repeats the same 29 body fields and adds two seal records:

- `package`: path, size, and SHA-256 of `package.tar.gz`.
- `body`: path, size, and SHA-256 of the enclosed
  `validation-body.json` member.

Failure paths are unchanged: a `blocked-*` or `incomplete` result has no
package and no body seal record, exactly as before.

## Roster membership

`validation-body.json` is a member of the fixed local evidence roster
checked by `check_evidence_roster` (105 fixed names plus the per-node
report records, 128 members in total). Dropping it from the package
fails the roster check; changing its bytes without resealing breaks the
inner manifest compare; resealing without updating the envelope breaks
the body seal.

## Verification order

The light verifier (no Docker) parses the envelope, validates both seal
record shapes, rehashes the archive, streams and compares every member,
checks the fixed roster, and only then compares the enclosed body
against the envelope minus its two seal records. Candidate, policy, and
completeness gates are evaluated from the *enclosed* body alone: an
envelope-only tamper diverges from the sealed body and is rejected
before any gate sees it. The heavy replay entry receives the same
enclosed body and refuses any value that still carries seal records.

## Anchor distribution

The envelope is not self-authenticating: its seal strings are claims
until they are recomputed against package bytes. Publication and
custody flows must therefore carry the trust anchor separately from the
envelope — the same out-of-band rule that already applies to package
digests. Custody facts record the recomputed `body_sha256` alongside
`package_sha256`, and the frozen-payload inspection re-streams the
payload's own `package.tar.gz` to check it, never trusting the envelope
string.
