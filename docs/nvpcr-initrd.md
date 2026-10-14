# RFC: set up NvPCRs in the initrd (systemd 262+)

Status: **draft**. Design only. Do not implement the TPM side until gotpm
lands. See Discussion [#424](https://github.com/anatol/booster/discussions/424).

## What is broken

On systemd 262, NvPCRs (extra “PCR-like” registers in TPM NV) must get their
**first write in the initrd**. You cannot finish that after `switch_root`.

systemd’s own initrd does it with `systemd-tpm2-setup --early`. Booster never
runs that. So the real root boots, then units fail with:

`Failed to initialize NvPCR index: No such file or directory`

Common failures: `systemd-tpm2-setup-early.service`,
`systemd-pcrproduct.service`, `systemd-pcrlogin@.service`.

This is **not** about LUKS TPM unlock. Unlock can work while NvPCR setup still
fails.

## What the maintainer said to do (#424)

In Booster init, **before any TPM unlock**:

1. Wait for the TPM.
2. Extend `enter-initrd` on PCR 11 (we already have `ensureEnterInitrdBarrier`).
3. Create or migrate each NvPCR from the `.nvpcr` files in the image.
4. Do the signed first write.
5. Leave state so the host can find the indexes (mainly
   `/run/systemd/nvpcr/<name>.auth`).
6. Only run this if the UKI has initrd PCR signatures (`SignInitrdPCRs=yes`).
   Otherwise skip.

Do this after #434, #433, and the move to gotpm.

## What systemd expects

From systemd 262 (`tpm2_nvpcr_initialize` / `systemd-tpm2-setup --early`):

| Thing | Rule |
| --- | --- |
| Definitions | `*.nvpcr` JSON under `/usr/lib/nvpcr/` (also `/etc/nvpcr`, …). Fields: `name`, `algorithm` (sha256 for now), `nvIndex`, optional `priority` (lower first), optional `orderly`. |
| In the UKI | Those files must be in the UKI. Booster puts them in the initrd section. |
| Signatures | Initrd-phase policy with ref `initrd`. Stub puts them at `/.extra/tpm2-pcr-signature.json` and `/.extra/tpm2-pcr-public-key.pem`. |
| Write policy | First write: PolicyAuthorize with ref `initrd`. Later writes: PolicyNvWritten(true). Combined with PolicyOR. |
| PCR for Authorize | PCR 11 only. |
| First write | Extend with a zero digest under that signed policy. |
| Handoff | Write `/run/systemd/nvpcr/<name>.auth` (hex of the Authorize branch digest). If missing, the host treats the NvPCR as not set up. |
| PCR 9 | Also extend PCR 9 with `nvpcr-init:<name>:0x<index>:<nvNameHex>`. |
| Order | Sort by `priority`, then name. If NV space is full, skip the rest (do not fail the boot). |
| Old format | Old “anchor secret” NvPCRs need upgrade. Cleaning old cred files is mostly a host job. |
| When to skip | No initrd signature / no public key → do nothing. |

## Changes

### 1. Generator (this PR)

Copy `/usr/lib/nvpcr/*.nvpcr` and `/etc/nvpcr/*.nvpcr` into the image.

If the host has no such files, that is fine.

UKI build still needs `SignInitrdPCRs=yes` and the PCR public key. Booster does
not create those signatures.

### 2. Init (later, after gotpm)

Add something like `init/nvpcr.go`. Call it from `boost()` after `/run` exists
and the TPM is ready, **before** unlock:

```text
tpmAwaitReady()
ensureEnterInitrdBarrier()          // already exists; call early if NvPCR is on
maybe write SRK pubkey under /run/systemd/   // optional
initialize NvPCRs from the image
… unlock root …
applyBootPhaseForwardLock()         // already exists at switch_root
```

Run only if all of these are true:

- At least one `*.nvpcr` file in the image
- `/.extra/tpm2-pcr-public-key.pem` exists
- Signature JSON has a usable `initrd` entry for PCR 11

On errors:

- No TPM / no NvPCR support → warn, keep booting
- One index fails → count it, keep going, still unlock
- Missing signatures/keys → skip quietly

Reuse:

- `ensureEnterInitrdBarrier` / `measurePhaseToPCR11` (do not change the PCR11 bytes)
- Signature lookup next to `resolveSignature`
- Prefer gotpm for the new NV / policy code; do not grow the old legacy TPM path

### 3. Manpage (with the init work)

Say users need:

1. `.nvpcr` files in the Booster image
2. UKI with `SignInitrdPCRs=yes` and the PCR public key
3. systemd 262+ on the host

## Out of scope

- Binding LUKS to NvPCRs
- Argon2id PIN (#433)
- Shipping `systemd-tpm2-setup` inside Booster
- Cleaning ESP creds on the host

## Tests (when init exists)

- Parse `.nvpcr`, sort by priority, enable on/off
- With swtpm: create index, first signed write, write `.auth`, later extend
- Full UKI boot with `SignInitrdPCRs=yes`: product/login units succeed; `.auth` files exist before switch_root
- No signatures: skip; LUKS TPM unlock still works

## Open questions

1. Also write `/run/systemd/tpm2-srk-public-key.*`, or only NvPCR + `.auth`?
2. Pack `/etc/nvpcr` too, or only `/usr/lib/nvpcr`?
3. Is putting files in the initrd enough for “in the UKI”, or do non-ukify setups need another section?
