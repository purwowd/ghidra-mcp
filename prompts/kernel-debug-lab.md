# Kernel / driver lab (Ghidra + MCP)

Lab-only. Live kernel debug can BSOD the guest — snapshot first. Never load experimental drivers on the primary host.

## Static (any .sys / driver-like PE)

```text
kernel_driver_triage
decompile DriverEntry / GsDriverEntry
# find MajorFunction[IRP_MJ_*] assignments + DeviceIoControl handlers
```

Cursor Assist: **Tools ▾ → Kernel triage**.

## Live KD playbook

```text
kernel_debug_playbook
```

Typical host/guest split:

1. Windows guest: `bcdedit /debug on` + network/serial debug per hypervisor
2. WinDbg attach → `bp driver!DriverEntry`
3. Ghidra: static map of IOCTL surface while KD runs in the guest tool chain

## Detonation of usermode loaders that drop .sys

Use `./scripts/detonate-lab.sh full <label>` then import the dropped `.sys` and run `kernel_driver_triage`.

## Safety

See `ai_agent_instructions/16_RE_MALWARE_ANALYSIS.md`.
