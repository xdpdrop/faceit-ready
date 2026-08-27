# XDPDROP — FACEIT Anti-Cheat Requirements Checker

A single PowerShell script that tells you, in about five seconds, why FACEIT Anti-Cheat won't let you into a match.

---

## What it checks

FACEIT enforces a growing set of hardware and OS security requirements. This script validates all of them at once:

| Requirement | Why FACEIT wants it |
|---|---|
| **TPM 2.0** | Mandatory for every player since 25 Nov 2025 |
| **Secure Boot** | Verifies the boot chain wasn't tampered with |
| **IOMMU / DMA Protection** | Blocks DMA-based hardware cheats |
| **Virtualization (VT-x / AMD SVM)** | Required for VBS |
| **VBS + Memory Integrity (HVCI)** | Rolled out in waves, per account |
| **UEFI + GPT** | Prerequisite for Secure Boot |
| **Windows 11 23H2+** | Windows 10 blocked from 14 Oct 2026 |
| **Boot integrity flags** | Test signing / kernel debug will get you rejected |
| **TPM attestation readiness** | EK certificate, attestation capability, firmware health |

---

## Usage

Open PowerShell **as Administrator**, then:

```powershell
Unblock-File .\Test-FaceitRequirements.ps1
.\Test-FaceitRequirements.ps1
```

Blocked by execution policy? Pipe it in instead:

```powershell
Get-Content .\Test-FaceitRequirements.ps1 -Raw | Invoke-Expression
```

---

## Requirements

- Windows 10 1809+ or Windows 11
- PowerShell 5.1 or newer
- Administrator rights for full results

---

## Keywords

FACEIT anti-cheat error, TPM 2.0 not detected, Secure Boot disabled FACEIT, IOMMU FACEIT, DMA protection CS2, FACEIT AC requirements checker, Windows 11 FACEIT, TPM attestation PowerShell, CS2 anti-cheat fix.

---

**XDPDROP**