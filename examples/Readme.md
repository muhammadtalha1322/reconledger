# Examples

This directory is reserved for sample scan output and generated reports.

Due to the nature of reconnaissance data, no real scan output is committed
to this repository. Examples would expose target infrastructure details and
are therefore excluded via `.gitignore`.

## Generating a Sample Report

To generate a report against a lab target you control:

```bash
# Run the scanner
sudo bash reconledger.sh --full yourtarget.local

# If you skipped report generation during the scan, run it manually
python3 reconledger_report.py ~/Documents/reconledger_yourtarget.local_20260101_120000
```

The report opens in any modern browser. Use the **Print / Save as PDF** button
in the report header to produce a PDF version without any additional tools.

## Lab Environment Suggestions

- OWASP WebGoat
- DVWA (Damn Vulnerable Web Application)
- HackTheBox or TryHackMe retired machines
- Your own VPS with intentional misconfigurations for testing
