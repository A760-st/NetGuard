We are moving to Phase 5 (the final phase) of our NTRO Non-IoC Network Flow Anomaly Detection project. Please write the Go packet sniffer and containerization configuration.

Create two files in the workspace root:

1. sniffer.go:
   - Implement a lightweight Go program using `github.com/google/gopacket` and `github.com/redis/go-redis/v9`.
   - Sniff network packets on a configurable interface (default: "en0" or "eth0").
   - Aggregate packets into 5-tuple flows (src_ip, dst_ip, src_port, dst_port, protocol) over a sliding time window (e.g., 5 seconds).
   - Compute the required 12 runtime features (flow duration, packet counts, byte totals, lengths, inter-arrival times, TCP flags, and byte asymmetry ratio).
   - Push the formatted flow JSON payload into the Redis queue ("ntro:flow_queue").

2. Dockerfile:
   - Create a multi-stage Dockerfile or container configuration suitable for deploying the FastAPI backend and Python ML pipeline to Google Cloud Run.
   - Ensure PyTorch CPU wheels, Prisma client generation, and model artifacts are correctly bundled.

Keep the code clean, modular, and well-commented.