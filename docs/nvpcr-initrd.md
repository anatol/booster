# NvPCRs in the initrd (systemd 262+)

Status: **implemented** on branch `rfc/nvpcr-initrd` (draft PR). Matches
systemd 262 `tpm2_nvpcr_initialize` / `systemd-tpm2-setup --early`.

## What was broken

On systemd 262, NvPCRs (extra “PCR-like” registers in TPM NV) must get their
**first write in the initrd**. You cannot finish that after `switch_root`.

systemd’s own initrd does it with `systemd-tpm2-setup --early`. Booster never
ran that. So the real root boots, then units fail with:

`Failed to initialize NvPCR index: No such file or directory`

Common failures: `systemd-tpm2-setup-early.service`,
`systemd-pcrproduct.service`, `systemd-pcrlogin@.service`.

This is **not** about LUKS TPM unlock. Unlock can work while NvPCR setup still
fails.

## Contract (systemd 262)

| Thing | Rule |
| --- | --- |
| Definitions | `*.nvpcr` JSON under `/usr/lib/nvpcr/` (also `/etc/nvpcr`, `/run/nvpcr`). Fields: `name`, `algorithm` (sha256 for now), `nvIndex`, optional `priority` (lower first), optional `orderly`. |
| In the UKI | Those files must be in the image. Generator packs them. |
| Signatures | Initrd-phase policy with ref `initrd` (= SHA256 of the string). Stub puts them at `/.extra/tpm2-pcr-signature.json` and `/.extra/tpm2-pcr-public-key.pem`. |
| Write policy | `PolicyOR(PolicyAuthorize(pubkey, ref=initrd), PolicyNvWritten(true))`. |
| PCR for Authorize | PCR 11 only, after `enter-initrd`. |
| First write | `NV_Extend` with a zero digest under that signed policy. |
| Handoff | `/run/systemd/nvpcr/<name>.auth` = hex of the Authorize branch digest. |
| PCR 9 | Also extend PCR 9 with `nvpcr-init:<name>:0x<index>:<nvNameHex>` (name after WRITTEN is set). |
| Order | Sort by `priority`, then name. If NV space is full, skip the rest. |
| When to skip | No defs / no public key / no signature JSON → do nothing. |

## What Booster does

### Generator

Copies `/usr/lib/nvpcr/*.nvpcr` and `/etc/nvpcr/*.nvpcr` into the image.

UKI build still needs `SignInitrdPCRs=yes` and the PCR public key. Booster does
not create those signatures.

### Init

`init/nvpcr.go` + `init/tpm_nvextend.go`:

1. Wait for TPM (`tpmAwaitReady` + `openTPM`).
2. `ensureEnterInitrdBarrier()` (PCR 11).
3. Load defs, public key, signature JSON.
4. For each NvPCR (priority order): define/reuse NV index, signed first write,
   write `.auth`, extend PCR 9.
5. Called from `boost()` before waiting for root, and again from
   `recoverSystemdTPM2Password` (`sync.Once`) so a fast LUKS race cannot skip it.

`NV_Extend` is hand-rolled: go-tpm v0.9.8 has `TPMCCNVExtend` but no typed
wrapper.

On errors: warn and keep booting (same as systemd’s early setup). Missing
signatures/keys → skip quietly.

## What users need

1. `.nvpcr` files on the build host (packed into the image)
2. UKI with `SignInitrdPCRs=yes` and the PCR public key
3. systemd 262+ on the host

## Out of scope

- Binding LUKS to NvPCRs
- Shipping `systemd-tpm2-setup` inside Booster
- Cleaning ESP / old anchor creds on the host
- swtpm end-to-end first-write test (unit tests cover policy/parse/attrs; live
  TPM path still needs a UKI boot smoke test)

## Open questions

1. Also write `/run/systemd/tpm2-srk-public-key.*`, or only NvPCR + `.auth`?
2. Is packing into the initrd enough for every UKI builder, or do some setups
   need another PE section?
