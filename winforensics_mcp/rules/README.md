# Bundled YARA Rules

These rules are sourced from [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base), a high-quality collection of YARA rules maintained by Florian Roth (Nextron Systems).

## Statistics

| Metric | Count |
|--------|-------|
| Total rule files | 732 |
| Usable rules | 718 |
| Skipped (external vars) | 14 |
| Total size | ~8.4 MB |

## Rule Categories

| Prefix | Description | Example |
|--------|-------------|---------|
| `apt_*` | Advanced Persistent Threat groups | `apt_lazarus_aug20.yar` |
| `crime_*` | Crimeware and ransomware | `crime_emotet.yar` |
| `gen_*` | Generic detection patterns | `gen_mimikatz.yar` |
| `expl_*` | Exploit detection | `expl_log4j_cve_2021_44228.yar` |
| `mal_*` | Malware families | `mal_lockbit_lnx_macos_apr23.yar` |
| `hktl_*` | Hacking tools | `hktl_bruteratel_c4_badger.yar` |
| `pua_*` | Potentially unwanted apps | `pua_cryptocoin_miner.yar` |
| `vul_*` | Vulnerable components | `vul_cve_2020_0688.yar` |

## Skipped Rules

Some rules use external variables (`filename`, `filepath`, `extension`) that are only available when using THOR/LOKI scanners. These are automatically skipped:

- `configured_vulns_ext_vars.yar`
- `expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar`
- `expl_connectwise_screenconnect_vuln_feb24.yar`
- `gen_fake_amsi_dll.yar`
- `gen_mal_3cx_compromise_mar23.yar`
- `gen_susp_obfuscation.yar`
- `gen_vcruntime140_dll_sideloading.yar`
- `gen_webshells_ext_vars.yar`
- `general_cloaking.yar`
- `generic_anomalies.yar`
- `thor_inverse_matches.yar`
- `yara-rules_vuln_drivers_strict_renamed.yar`
- `yara_mixed_ext_vars.yar`
- `gen_case_anomalies.yar`
- `gen_anomalies_keyword.yar`

## License

These rules are licensed under their original terms from signature-base.
See each rule file for specific licensing information.

Most rules are CC-BY-NC 4.0 (Florian Roth / Nextron Systems).

## Updating Rules

To update to the latest rules:

```bash
cd winforensics_mcp/rules
rm -f *.yar  # Remove old rules

# Clone and copy new rules
git clone --depth 1 https://github.com/Neo23x0/signature-base /tmp/sig-base
cp /tmp/sig-base/yara/*.yar .
rm -rf /tmp/sig-base
```

## Adding Custom Rules

Simply place `.yar` or `.yara` files in this directory. They will be automatically discovered and compiled.

If a rule fails to compile due to undefined identifiers, add its filename to `EXTERNAL_VAR_FILES` in `yara_scanner.py`.
