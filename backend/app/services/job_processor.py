import os
import time
import uuid
import hashlib
import asyncio
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select, update

from app.core.logging import get_logger
from app.core.config import get_settings
from app.database.connection import async_session_factory
from app.models.analysis_job import AnalysisJob, PARSER_VERSION, FEATURE_SCHEMA_VERSION, DETECTOR_CONFIG_VERSION
from app.models.flow import Flow
from app.models.alert import Alert
from app.models.detector_result import DetectorResult as DetectorResultModel
from app.models.host_risk import HostRiskScore
from app.services.pcap_parser import parse_pcap, PcapPacket
from app.services.flow_engine import build_flows, FlowRecord
from app.services.feature_engine import compute_features, FEATURE_NAMES
from app.services.alert_dedup import deduplicate_alerts
from app.risk.risk_engine import calculate_risk_score, classify_severity, calculate_host_risk
from app.correlation.incident_correlator import correlate_alerts
from app.detectors.registry import ALL_DETECTORS

logger = get_logger("job_processor")
settings = get_settings()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

_active_jobs: dict[str, asyncio.Task] = {}
_job_progress: dict[str, float] = {}

_anomaly_engine = None


def get_job_progress(job_id: str) -> float:
    return _job_progress.get(job_id, 0.0)


def _get_anomaly_engine():
    global _anomaly_engine
    if _anomaly_engine is None:
        try:
            from ml.inference.anomaly_inference import AnomalyInferenceEngine
            _anomaly_engine = AnomalyInferenceEngine(settings.ml_models_dir)
            _anomaly_engine.load()
        except Exception:
            _anomaly_engine = False
    return _anomaly_engine if _anomaly_engine is not False else None


def _compute_file_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _compute_data_quality(packets: list[PcapPacket], flow_records: list[FlowRecord]) -> dict:
    total_packets = len(packets)
    ipv4_count = sum(1 for p in packets if not p.is_ipv6)
    ipv6_count = sum(1 for p in packets if p.is_ipv6)
    tcp_count = sum(1 for p in packets if p.protocol == 6)
    udp_count = sum(1 for p in packets if p.protocol == 17)
    icmp_count = sum(1 for p in packets if p.protocol == 1)
    other_proto = total_packets - tcp_count - udp_count - icmp_count
    no_ip = sum(1 for p in packets if not p.src_ip or not p.dst_ip)

    proto_dist = Counter(p.protocol for p in packets)
    port_dist = Counter(p.dst_port for p in packets if p.dst_port > 0)
    fwd_bytes_total = sum(fr.forward_bytes for fr in flow_records)
    bwd_bytes_total = sum(fr.backward_bytes for fr in flow_records)
    unique_src = len(set(fr.source_ip for fr in flow_records))
    unique_dst = len(set(fr.destination_ip for fr in flow_records))

    return {
        "total_packets": total_packets,
        "ipv4_packets": ipv4_count,
        "ipv6_packets": ipv6_count,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "icmp_packets": icmp_count,
        "other_protocol_packets": other_proto,
        "packets_without_ip": no_ip,
        "total_flows": len(flow_records),
        "unique_source_ips": unique_src,
        "unique_destination_ips": unique_dst,
        "forward_bytes_total": fwd_bytes_total,
        "backward_bytes_total": bwd_bytes_total,
        "total_bytes": fwd_bytes_total + bwd_bytes_total,
        "top_destination_ports": dict(port_dist.most_common(20)),
        "protocol_distribution": {str(k): v for k, v in proto_dist.most_common()},
    }


async def create_job(file_path: str, file_size: int, filename: str) -> str:
    job_id = uuid.uuid4()
    async with async_session_factory() as db:
        job = AnalysisJob(
            id=job_id,
            filename=filename,
            file_size=file_size,
            status="queued",
            progress=0.0,
        )
        db.add(job)
        await db.commit()
    return str(job_id)


async def start_job_processing(job_id: str, file_path: str) -> None:
    task = asyncio.create_task(_process_job(job_id, file_path))
    _active_jobs[job_id] = task


async def cancel_job_processing(job_id: str) -> bool:
    task = _active_jobs.get(job_id)
    if task and not task.done():
        task.cancel()
        async with async_session_factory() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == uuid.UUID(job_id))
                .values(status="cancelled")
            )
            await db.commit()
        return True
    return False


def _build_features_map(flow_records: list[FlowRecord]) -> dict:
    features_map = {}
    for fr in flow_records:
        feat = compute_features(
            duration=fr.duration,
            fwd_packets=fr.forward_packets,
            bwd_packets=fr.backward_packets,
            fwd_bytes=fr.forward_bytes,
            bwd_bytes=fr.backward_bytes,
            forward_packet_lengths=fr.forward_packet_lengths,
            backward_packet_lengths=fr.backward_packet_lengths,
            forward_timestamps=fr.forward_timestamps,
            backward_timestamps=fr.backward_timestamps,
            syn_count=fr.syn_count,
            ack_count=fr.ack_count,
            fin_count=fr.fin_count,
            rst_count=fr.rst_count,
            psh_count=fr.psh_count,
        )
        key = f"{fr.source_ip}:{fr.source_port}-{fr.destination_ip}:{fr.destination_port}-{fr.protocol}"
        features_map[key] = feat
    return features_map


async def _process_job(job_id: str, file_path: str) -> None:
    start_time = time.time()
    logger.info("job_processing_started", job_id=job_id, file_path=file_path)

    try:
        async with async_session_factory() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == uuid.UUID(job_id))
                .values(status="processing", progress=0.0)
            )
            await db.commit()

        _job_progress[job_id] = 0.05

        file_sha256 = _compute_file_sha256(file_path)

        packets = parse_pcap(file_path)
        total_packets = len(packets)
        logger.info("pcap_parsed", job_id=job_id, packet_count=total_packets)

        _job_progress[job_id] = 0.20
        await _update_progress(job_id, 0.20, packet_count=total_packets)

        flow_records = build_flows(packets)
        total_flows = len(flow_records)
        logger.info("flows_built", job_id=job_id, flow_count=total_flows)

        _job_progress[job_id] = 0.35
        await _update_progress(job_id, 0.35)

        features_map = _build_features_map(flow_records)
        logger.info("features_computed", job_id=job_id, feature_count=len(features_map))

        _job_progress[job_id] = 0.45
        await _update_progress(job_id, 0.45)

        flow_uuid_map: dict[str, uuid.UUID] = {}
        async with async_session_factory() as db:
            for fr in flow_records:
                key = f"{fr.source_ip}:{fr.source_port}-{fr.destination_ip}:{fr.destination_port}-{fr.protocol}"
                feat = features_map.get(key)
                flow_uuid = uuid.uuid5(
                    uuid.NAMESPACE_OID, f"flow|{job_id}|{key}"
                )
                flow_uuid_map[key] = flow_uuid

                anomaly_score = None
                engine = _get_anomaly_engine()
                if engine and feat:
                    try:
                        result = engine.predict_single(feat.to_vector())
                        anomaly_score = result.get("anomaly_score", 0.0)
                    except Exception:
                        pass

                flow_features = feat.to_dict() if feat else {}
                if fr.dns_query_names:
                    flow_features["dns_query_names"] = fr.dns_query_names

                flow_record = Flow(
                    id=flow_uuid,
                    job_id=uuid.UUID(job_id),
                    source_ip=fr.source_ip,
                    destination_ip=fr.destination_ip,
                    source_port=fr.source_port if fr.source_port > 0 else None,
                    destination_port=fr.destination_port if fr.destination_port > 0 else None,
                    protocol=fr.protocol,
                    first_seen=datetime.fromtimestamp(fr.first_seen, tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(fr.last_seen, tz=timezone.utc),
                    duration=fr.duration,
                    forward_packets=fr.forward_packets,
                    backward_packets=fr.backward_packets,
                    forward_bytes=fr.forward_bytes,
                    backward_bytes=fr.backward_bytes,
                    features=flow_features,
                    anomaly_score=anomaly_score,
                )
                db.add(flow_record)
            await db.commit()

        _job_progress[job_id] = 0.55
        await _update_progress(job_id, 0.55, flow_count=total_flows)

        all_detector_results = []
        for detector in ALL_DETECTORS:
            try:
                results = detector.detect(flow_records, features_map)
                all_detector_results.extend(results)
                logger.info("detector_completed", detector=detector.name, detections=len(results))

                async with async_session_factory() as db:
                    dr = DetectorResultModel(
                        job_id=uuid.UUID(job_id),
                        detector_name=detector.name,
                        threat_class=(
                            detector.threat_class.value
                            if hasattr(detector.threat_class, "value")
                            else str(detector.threat_class)
                        ),
                        status="completed",
                        confidence=max((r.confidence for r in results), default=0.0),
                        detections_count=len(results),
                    )
                    db.add(dr)
                    await db.commit()

            except Exception as e:
                logger.error("detector_failed", detector=detector.name, error=str(e))
                async with async_session_factory() as db:
                    dr = DetectorResultModel(
                        job_id=uuid.UUID(job_id),
                        detector_name=detector.name,
                        threat_class="Unknown",
                        status="failed",
                        confidence=0.0,
                        detections_count=0,
                        error_message=str(e)[:500],
                    )
                    db.add(dr)
                    await db.commit()

        _job_progress[job_id] = 0.70
        await _update_progress(job_id, 0.70)

        deduplicated = deduplicate_alerts(all_detector_results)
        logger.info("alerts_deduplicated", job_id=job_id, raw=len(all_detector_results), deduplicated=len(deduplicated))

        async with async_session_factory() as db:
            for alert_data in deduplicated:
                risk = calculate_risk_score(
                    confidence=alert_data["confidence"],
                    severity=alert_data["severity"],
                    occurrence_count=alert_data.get("occurrence_count", 1),
                )
                alert = Alert(
                    job_id=uuid.UUID(job_id),
                    flow_id=flow_uuid_map.get(alert_data.get("flow_id")),
                    source_ip=alert_data["source_ip"],
                    destination_ip=alert_data["destination_ip"],
                    threat_class=alert_data["threat_class"],
                    confidence=alert_data["confidence"],
                    risk_score=risk,
                    severity=classify_severity(risk),
                    supporting_evidence=alert_data.get("supporting_evidence"),
                    detector_name=alert_data["detector_name"],
                    status="new",
                    fingerprint=alert_data.get("fingerprint"),
                    occurrence_count=alert_data.get("occurrence_count", 1),
                )
                db.add(alert)
            await db.commit()

        _job_progress[job_id] = 0.80
        await _update_progress(job_id, 0.80)

        await correlate_alerts(job_id, deduplicated)

        _job_progress[job_id] = 0.90
        await _update_progress(job_id, 0.90)

        await _compute_host_risks(job_id, flow_records, all_detector_results)

        data_quality = _compute_data_quality(packets, flow_records)

        duration = time.time() - start_time
        _job_progress[job_id] = 1.0

        async with async_session_factory() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == uuid.UUID(job_id))
                .values(
                    status="completed",
                    progress=1.0,
                    flow_count=total_flows,
                    alert_count=len(deduplicated),
                    processing_duration=duration,
                    completed_at=datetime.now(timezone.utc),
                    file_sha256=file_sha256,
                    parser_version=PARSER_VERSION,
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                    detector_config_version=DETECTOR_CONFIG_VERSION,
                    data_quality=data_quality,
                )
            )
            await db.commit()

        logger.info(
            "job_processing_completed",
            job_id=job_id,
            duration=duration,
            packets=total_packets,
            flows=total_flows,
            alerts=len(deduplicated),
        )

    except asyncio.CancelledError:
        logger.info("job_cancelled", job_id=job_id)
        raise
    except Exception as e:
        logger.error("job_processing_failed", job_id=job_id, error=str(e))
        try:
            async with async_session_factory() as db:
                await db.execute(
                    update(AnalysisJob)
                    .where(AnalysisJob.id == uuid.UUID(job_id))
                    .values(status="failed", error_message=str(e)[:1000])
                )
                await db.commit()
        except Exception:
            pass
    finally:
        _active_jobs.pop(job_id, None)
        _job_progress.pop(job_id, None)


async def _compute_host_risks(
    job_id: str,
    flow_records: list[FlowRecord],
    detector_results: list,
) -> None:
    from collections import defaultdict

    host_flows = defaultdict(int)
    host_alerts_data = defaultdict(list)
    host_anomalies = defaultdict(list)

    for fr in flow_records:
        host_flows[fr.source_ip] += 1

    for dr in detector_results:
        host_alerts_data[dr.source_ip].append(
            {
                "risk_score": dr.confidence * 100,
                "confidence": dr.confidence,
                "severity": dr.severity.value if hasattr(dr.severity, "value") else str(dr.severity),
            }
        )

    async with async_session_factory() as db:
        for ip in set(list(host_flows.keys()) + list(host_alerts_data.keys())):
            risk_data = calculate_host_risk(
                host_alerts=host_alerts_data.get(ip, []),
                host_flows=host_flows.get(ip, 0),
                anomaly_scores=host_anomalies.get(ip, []),
            )
            host_risk = HostRiskScore(
                job_id=uuid.UUID(job_id),
                ip_address=ip,
                risk_score=risk_data["risk_score"],
                severity=risk_data["severity"],
                alert_count=risk_data["alert_count"],
                flow_count=risk_data["flow_count"],
                anomaly_score=risk_data["anomaly_score"],
            )
            db.add(host_risk)
        await db.commit()


async def _update_progress(
    job_id: str,
    progress: float,
    packet_count: int | None = None,
    flow_count: int | None = None,
) -> None:
    _job_progress[job_id] = progress
    try:
        async with async_session_factory() as db:
            values: dict = {"progress": progress}
            if packet_count is not None:
                values["packet_count"] = packet_count
            if flow_count is not None:
                values["flow_count"] = flow_count
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == uuid.UUID(job_id))
                .values(**values)
            )
            await db.commit()
    except Exception as e:
        logger.error("progress_update_failed", job_id=job_id, error=str(e))
