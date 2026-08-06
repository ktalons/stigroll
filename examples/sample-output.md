# Sample output

Produced by:

```bash
python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml --format markdown
```

---

# STIG Findings Rollup

**Hosts:** 1 (WORKSTATION-01)  
**Rules evaluated:** 256  
**Open findings:** 12

## Open findings by severity

| Category | Open |
|---|---:|
| CAT I | 2 |
| CAT II | 10 |
| CAT III | 0 |

## All results by status

| Status | Count |
|---|---:|
| open | 12 |
| not a finding | 7 |
| not applicable | 1 |
| not reviewed | 236 |

## Open findings by NIST 800-53 control family

| Family | Name | CAT I | CAT II | CAT III | Total |
|---|---|---:|---:|---:|---:|
| AU | Audit and Accountability | 0 | 5 | 0 | 5 |
| CM | Configuration Management | 1 | 2 | 0 | 3 |
| AC | Access Control | 0 | 2 | 0 | 2 |
| SI | System and Information Integrity | 0 | 1 | 0 | 1 |
| MA | Maintenance | 1 | 0 | 0 | 1 |
| SC | System and Communications Protection | 0 | 1 | 0 | 1 |

## CAT I open findings

| Rule | Host | Controls | Title |
|---|---|---|---|
| V-253370 | WORKSTATION-01 | CM-6 | Credential Guard must be running on Windows 11 systems. |
| V-253418 | WORKSTATION-01 | MA-4 | The Windows Remote Management (WinRM) service must not use Basic authentication. |

