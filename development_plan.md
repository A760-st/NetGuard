We are building an **AI/ML-based cybersecurity tool that detects whether a system, firewall, router, or network has been compromised**.
Unlike traditional security tools, it should **not rely only on known IoCs** such as malicious IPs, domains, or file hashes.
The system will learn **normal network/system behavior** and identify significant deviations as potential compromises.
We will initially develop and test the ML model using a **pre-built cybersecurity dataset**.
We will extract relevant network-flow features and build a baseline anomaly-detection model.
After validating the model, we will integrate **live network-traffic capture** and feed it through the same feature pipeline.
The final prototype should provide **real-time anomaly detection, risk/alert reporting, and explanations for detected anomalies**.

Plan- 

development is broken down into 5 logical, incremental phases, ensuring every phase delivers a working, testable component without over-engineering. Relevant MCP services (Neon, Prisma, Redis, Cloud Run) are integrated cleanly where they add practical engineering value.

Phase 1: Dataset Preprocessing & Feature Extraction Pipeline
Objective: Ingest raw benchmark network flow logs (e.g., CIC-IDS2017 CSVs), clean and scale the data, and isolate a lightweight subset of 12 core runtime features (e.g., inter-arrival times, packet byte sizes, flow duration).


Components / Files to Build:


data_loader.py: Script to ingest and parse CSV flow logs.


preprocessing.py: Implements feature selection and StandardScaler fitting on benign training traffic.


Technologies Required: Python, Pandas, Scikit-learn, NumPy.


Dependencies: CIC-IDS2017 dataset files locally available.


What the Next Phase Adds: Feeds the normalized, clean feature tensors into the unsupervised machine learning model.


Phase 2: Unsupervised ML Training & Inference Engine
Objective: Build and train a Deep Autoencoder in PyTorch on 100% benign traffic to establish normal network behavior baselines and compute reconstruction loss ($\mathcal{L}_{\text{MSE}}$) with dynamic thresholding ($\tau$).


Components / Files to Build:


model.py: PyTorch Deep Autoencoder architecture definition.


train.py: Training script with loss monitoring.


inference.py: Evaluates new flow vectors and outputs raw reconstruction error scores.


Technologies Required: Python, PyTorch.


Dependencies: Phase 1 processed feature tensors and scaling parameters.


What the Next Phase Adds: Wraps the inference engine into a persistent backend API that translates raw model loss into normalized risk scores.


Phase 3: Database Storage & Risk Scoring Backend
Objective: Establish a persistent data layer and a FastAPI backend service that maps model reconstruction errors to a normalized network risk score ($0-100$) using exponential decay and stores anomaly logs.


Components / Files to Build:


schema.prisma: Database schema definition for flows, IPs, and anomaly records (managed via the PrismaMCP).


database.py: Database connection and session management (connected to Neon PostgreSQL via the NeonMCP).


risk_engine.py: Implements the sliding-window exponential decay risk scoring formula.


main.py: FastAPI server exposing endpoints for batch evaluation and risk score querying.


Technologies Required: Python, FastAPI, Prisma, Neon PostgreSQL, Pydantic.


Dependencies: Phase 2 trained model weights, configured Neon database instance.


What the Next Phase Adds: Introduces a real-time in-memory caching and buffering layer to handle high-throughput flow events asynchronously.


Phase 4: Real-Time Ingestion Buffer & API Integration
Objective: Implement an in-memory Redis message buffer to decouple real-time network flow ingestion from heavy ML inference, preventing request bottlenecks during traffic spikes.


Components / Files to Build:


redis_client.py: Redis connection handler and queue manager (leveraging the Redis MCP).


worker.py: Background consumer worker that pulls flows from the Redis queue, runs inference, and updates risk scores.


Technologies Required: Redis, Python (redis-py, asyncio).


Dependencies: Phase 3 FastAPI backend, active Redis instance.


What the Next Phase Adds: Connects the backend pipeline to a live packet capture utility and an interactive web visualization dashboard.


Phase 5: Live Packet Sniffer & SOC Dashboard Frontend
Objective: Build a high-performance packet capture collector and a clean web dashboard to monitor live network risk metrics and anomaly alerts in real time.


Components / Files to Build:


sniffer.go: Lightweight Go-based packet sniffer using gopacket to extract runtime flows and push them to the backend ingestion queue.


dashboard/: Lightweight React or Streamlit frontend displaying active IP risk scores and anomaly indicators.


Dockerfile: Container configuration for cloud deployment (ready for Cloud Run deployment via the Cloud Run MCP).


Technologies Required: Go (gopacket), Streamlit/React, Docker, Google Cloud Run.


Dependencies: Phase 4 backend APIs, Go runtime environment.


What the Next Phase Adds: Completes the end-to-end prototype, making it fully testable against live network traffic and ready for future multi-device host telemetry integration.

