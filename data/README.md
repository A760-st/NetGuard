# Sample PCAP Data

Place sample PCAP files in this directory for testing.

## Recommended Datasets

| Dataset | Use Case |
|---------|----------|
| CIC-IDS2017 | Intrusion detection evaluation |
| CIC-DDoS2019 | DDoS detection evaluation |
| CTU-13 | Botnet/C2 detection |
| CIC-Bell-DNS2021 | DNS analysis |

## Notes

- Do not commit large PCAP files to git.
- Use `.gitignore` to exclude `*.pcap` and `*.pcapng`.
- For CI testing, use small fixture PCAPs (< 1MB).
