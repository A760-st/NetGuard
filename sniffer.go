// sniffer.go
// ----------
// Phase 5 — Live Packet Sniffer
// NTRO Non-IoC Network Flow Anomaly Detection Project
//
// Captures live network packets using gopacket/pcap, aggregates them into
// 5-tuple flows over a configurable time window, computes the 12 runtime
// ML features, and pushes completed flow records as JSON into the Redis
// ingestion queue for the Phase 4 worker to consume.
//
// Build
// -----
//   go mod init ntro-sniffer
//   go mod tidy
//   go build -o sniffer sniffer.go
//   sudo ./sniffer --iface eth0 --window 5 --redis redis://localhost:6379/0
//
// Note: packet capture requires root / CAP_NET_RAW privileges.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	Iface       string        // network interface to sniff (e.g. "eth0", "en0")
	WindowSec   int           // flow aggregation window in seconds
	RedisURL    string        // Redis connection URL
	QueueName   string        // Redis list key for flow payloads
	SnapLen     int32         // pcap snapshot length in bytes
	Promiscuous bool          // enable promiscuous mode
	BPFFilter   string        // optional BPF packet filter expression
}

func defaultConfig() *Config {
	iface := os.Getenv("SNIFFER_IFACE")
	if iface == "" {
		iface = detectDefaultIface()
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}
	queueName := os.Getenv("REDIS_QUEUE_NAME")
	if queueName == "" {
		queueName = "ntro:flow_queue"
	}
	return &Config{
		Iface:       iface,
		WindowSec:   5,
		RedisURL:    redisURL,
		QueueName:   queueName,
		SnapLen:     65535,
		Promiscuous: true,
		BPFFilter:   "ip",
	}
}

// detectDefaultIface returns "eth0" on Linux, "en0" on macOS.
func detectDefaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return iface.Name
		}
	}
	return "eth0"
}

// ---------------------------------------------------------------------------
// Flow key — 5-tuple used as the aggregation bucket identifier
// ---------------------------------------------------------------------------

type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d→%s:%d/%s", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol)
}

// ---------------------------------------------------------------------------
// FlowRecord — accumulates per-packet stats within a time window
// ---------------------------------------------------------------------------

type FlowRecord struct {
	Key       FlowKey
	StartTime time.Time
	LastTime  time.Time

	// Packet counts
	FwdPkts int64
	BwdPkts int64

	// Byte totals (forward = src→dst, backward = dst→src)
	FwdBytes int64
	BwdBytes int64

	// Per-packet payload lengths (for mean computation)
	FwdLens []float64
	BwdLens []float64

	// Inter-arrival times (IAT) between consecutive packets (all directions)
	IATs     []float64
	LastPktTime time.Time

	// TCP flag counts
	SYNCount int64
	ACKCount int64
}

// AddPacket incorporates a single decoded packet into this flow record.
func (fr *FlowRecord) AddPacket(
	isFwd bool,
	payloadLen int,
	isSYN, isACK bool,
	capturedAt time.Time,
) {
	if !fr.LastPktTime.IsZero() {
		iat := capturedAt.Sub(fr.LastPktTime).Seconds() * 1e6 // microseconds
		if iat >= 0 {
			fr.IATs = append(fr.IATs, iat)
		}
	}
	fr.LastPktTime = capturedAt
	fr.LastTime = capturedAt

	plen := float64(payloadLen)
	if isFwd {
		fr.FwdPkts++
		fr.FwdBytes += int64(payloadLen)
		fr.FwdLens = append(fr.FwdLens, plen)
	} else {
		fr.BwdPkts++
		fr.BwdBytes += int64(payloadLen)
		fr.BwdLens = append(fr.BwdLens, plen)
	}

	if isSYN {
		fr.SYNCount++
	}
	if isACK {
		fr.ACKCount++
	}
}

// ---------------------------------------------------------------------------
// Feature computation helpers
// ---------------------------------------------------------------------------

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0.0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddev(vals []float64) float64 {
	if len(vals) < 2 {
		return 0.0
	}
	m := mean(vals)
	variance := 0.0
	for _, v := range vals {
		diff := v - m
		variance += diff * diff
	}
	variance /= float64(len(vals))
	return math.Sqrt(variance)
}

// FlowPayload is the JSON structure pushed to Redis — must match the
// FlowRecord Pydantic model in main.py and the CORE_FEATURES list.
type FlowPayload struct {
	// Metadata
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"srcIp"`
	DstIP     string `json:"dstIp"`
	SrcPort   uint16 `json:"srcPort"`
	DstPort   uint16 `json:"dstPort"`
	Protocol  string `json:"protocol"`

	// 12 core ML features (alias names match CORE_FEATURES in data_loader.py)
	FlowDuration        float64 `json:"Flow Duration"`
	TotFwdPkts          int64   `json:"Tot Fwd Pkts"`
	TotBwdPkts          int64   `json:"Tot Bwd Pkts"`
	TotLenFwdPkts       int64   `json:"TotLen Fwd Pkts"`
	TotLenBwdPkts       int64   `json:"TotLen Bwd Pkts"`
	FwdPktLenMean       float64 `json:"Fwd Pkt Len Mean"`
	BwdPktLenMean       float64 `json:"Bwd Pkt Len Mean"`
	FlowIATMean         float64 `json:"Flow IAT Mean"`
	FlowIATStd          float64 `json:"Flow IAT Std"`
	SYNFlagCnt          int64   `json:"SYN Flag Cnt"`
	ACKFlagCnt          int64   `json:"ACK Flag Cnt"`
	ByteAsymmetryRatio  float64 `json:"Byte_Asymmetry_Ratio"`
}

// ToPayload converts a completed FlowRecord into the Redis-ready JSON struct.
func (fr *FlowRecord) ToPayload() FlowPayload {
	durationMicros := fr.LastTime.Sub(fr.StartTime).Seconds() * 1e6

	// Byte_Asymmetry_Ratio = (TotLen Fwd Pkts + 1) / (TotLen Bwd Pkts + 1)
	bar := float64(fr.FwdBytes+1) / float64(fr.BwdBytes+1)

	return FlowPayload{
		Timestamp:           fr.StartTime.UTC().Format(time.RFC3339Nano),
		SrcIP:               fr.Key.SrcIP,
		DstIP:               fr.Key.DstIP,
		SrcPort:             fr.Key.SrcPort,
		DstPort:             fr.Key.DstPort,
		Protocol:            fr.Key.Protocol,
		FlowDuration:        durationMicros,
		TotFwdPkts:          fr.FwdPkts,
		TotBwdPkts:          fr.BwdPkts,
		TotLenFwdPkts:       fr.FwdBytes,
		TotLenBwdPkts:       fr.BwdBytes,
		FwdPktLenMean:       mean(fr.FwdLens),
		BwdPktLenMean:       mean(fr.BwdLens),
		FlowIATMean:         mean(fr.IATs),
		FlowIATStd:          stddev(fr.IATs),
		SYNFlagCnt:          fr.SYNCount,
		ACKFlagCnt:          fr.ACKCount,
		ByteAsymmetryRatio:  bar,
	}
}

// ---------------------------------------------------------------------------
// FlowTracker — thread-safe map of active flow records
// ---------------------------------------------------------------------------

type FlowTracker struct {
	mu      sync.Mutex
	flows   map[FlowKey]*FlowRecord
	windowD time.Duration
}

func NewFlowTracker(windowSec int) *FlowTracker {
	return &FlowTracker{
		flows:   make(map[FlowKey]*FlowRecord),
		windowD: time.Duration(windowSec) * time.Second,
	}
}

// AddPacket routes a decoded packet to the appropriate FlowRecord.
func (ft *FlowTracker) AddPacket(
	key FlowKey,
	isFwd bool,
	payloadLen int,
	isSYN, isACK bool,
	capturedAt time.Time,
) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	fr, exists := ft.flows[key]
	if !exists {
		fr = &FlowRecord{
			Key:       key,
			StartTime: capturedAt,
		}
		ft.flows[key] = fr
	}
	fr.AddPacket(isFwd, payloadLen, isSYN, isACK, capturedAt)
}

// Expire returns and removes all flow records whose window has elapsed.
func (ft *FlowTracker) Expire(now time.Time) []*FlowRecord {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	var expired []*FlowRecord
	for key, fr := range ft.flows {
		if now.Sub(fr.StartTime) >= ft.windowD {
			expired = append(expired, fr)
			delete(ft.flows, key)
		}
	}
	return expired
}

// FlushAll returns every active flow (used at shutdown).
func (ft *FlowTracker) FlushAll() []*FlowRecord {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	var all []*FlowRecord
	for key, fr := range ft.flows {
		all = append(all, fr)
		delete(ft.flows, key)
	}
	return all
}

// ---------------------------------------------------------------------------
// RedisPublisher — pushes JSON payloads to the Redis list queue
// ---------------------------------------------------------------------------

type RedisPublisher struct {
	client    *redis.Client
	queueName string
	ctx       context.Context
}

func NewRedisPublisher(redisURL, queueName string) (*RedisPublisher, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)
	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("cannot connect to Redis (%s): %w", redisURL, err)
	}
	log.Printf("[redis] Connected to %s, queue: %s", redisURL, queueName)
	return &RedisPublisher{client: client, queueName: queueName, ctx: ctx}, nil
}

// Push serialises a FlowPayload to JSON and appends it to the Redis list.
func (rp *RedisPublisher) Push(payload FlowPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("json.Marshal: %w", err)
	}
	if err := rp.client.RPush(rp.ctx, rp.queueName, data).Err(); err != nil {
		return fmt.Errorf("RPUSH %s: %w", rp.queueName, err)
	}
	return nil
}

// PushBatch pushes multiple payloads atomically via a Redis pipeline.
func (rp *RedisPublisher) PushBatch(payloads []FlowPayload) error {
	if len(payloads) == 0 {
		return nil
	}
	pipe := rp.client.Pipeline()
	for _, p := range payloads {
		data, err := json.Marshal(p)
		if err != nil {
			log.Printf("[redis] Skipping unserializable payload: %v", err)
			continue
		}
		pipe.RPush(rp.ctx, rp.queueName, data)
	}
	_, err := pipe.Exec(rp.ctx)
	return err
}

func (rp *RedisPublisher) Close() {
	_ = rp.client.Close()
}

// ---------------------------------------------------------------------------
// Packet decoding helper
// ---------------------------------------------------------------------------

// decodePacket extracts the 5-tuple and per-packet stats from a gopacket
// decoded packet.  Returns (key, isFwd, payloadLen, isSYN, isACK, ok).
// "Forward" is defined as src_port < dst_port for a canonical direction.
func decodePacket(packet gopacket.Packet) (FlowKey, bool, int, bool, bool, bool) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return FlowKey{}, false, 0, false, false, false
	}

	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()

	var srcPort, dstPort uint16
	var protocol string
	var isSYN, isACK bool
	var payloadLen int

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		// ICMP or other non-TCP/UDP — still track at IP level
		protocol = strings.ToUpper(netLayer.LayerType().String())
	} else {
		switch t := transportLayer.(type) {
		case *layers.TCP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
			protocol = "TCP"
			isSYN = t.SYN
			isACK = t.ACK
			payloadLen = len(t.Payload)
		case *layers.UDP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
			protocol = "UDP"
			payloadLen = len(t.Payload)
		default:
			protocol = transportLayer.LayerType().String()
		}
	}

	// Canonical direction: smaller port is always "src" for the flow key
	isFwd := srcPort <= dstPort
	key := FlowKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
	if !isFwd {
		// Swap to canonical form
		key.SrcIP, key.DstIP = dstIP, srcIP
		key.SrcPort, key.DstPort = dstPort, srcPort
	}

	return key, isFwd, payloadLen, isSYN, isACK, true
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	cfg := defaultConfig()

	// CLI flags (override env vars)
	flag.StringVar(&cfg.Iface, "iface", cfg.Iface, "Network interface to sniff (e.g. eth0, en0)")
	flag.IntVar(&cfg.WindowSec, "window", cfg.WindowSec, "Flow aggregation window in seconds")
	flag.StringVar(&cfg.RedisURL, "redis", cfg.RedisURL, "Redis URL (e.g. redis://localhost:6379/0)")
	flag.StringVar(&cfg.QueueName, "queue", cfg.QueueName, "Redis list key name for flow payloads")
	flag.StringVar(&cfg.BPFFilter, "filter", cfg.BPFFilter, "BPF packet filter expression")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[sniffer] Starting | iface=%s | window=%ds | redis=%s | queue=%s",
		cfg.Iface, cfg.WindowSec, cfg.RedisURL, cfg.QueueName)

	// ---- Open pcap handle ------------------------------------------------
	handle, err := pcap.OpenLive(
		cfg.Iface,
		cfg.SnapLen,
		cfg.Promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatalf("[sniffer] pcap.OpenLive(%s): %v", cfg.Iface, err)
	}
	defer handle.Close()

	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			log.Fatalf("[sniffer] SetBPFFilter(%q): %v", cfg.BPFFilter, err)
		}
		log.Printf("[sniffer] BPF filter set: %q", cfg.BPFFilter)
	}

	// ---- Connect to Redis ------------------------------------------------
	publisher, err := NewRedisPublisher(cfg.RedisURL, cfg.QueueName)
	if err != nil {
		log.Fatalf("[sniffer] Redis init: %v", err)
	}
	defer publisher.Close()

	// ---- Initialise flow tracker and expiry ticker -----------------------
	tracker := NewFlowTracker(cfg.WindowSec)
	ticker := time.NewTicker(time.Duration(cfg.WindowSec) * time.Second)
	defer ticker.Stop()

	// ---- Graceful shutdown via OS signals --------------------------------
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ---- Packet source ---------------------------------------------------
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packets := packetSource.Packets()

	// Counters for periodic logging
	var pktCount, flowCount int64

	log.Printf("[sniffer] Capturing on %s ...", cfg.Iface)

	for {
		select {
		// ---- New packet ---------------------------------------------------
		case packet, ok := <-packets:
			if !ok {
				log.Println("[sniffer] Packet source closed.")
				goto shutdown
			}
			pktCount++

			capturedAt := packet.Metadata().Timestamp
			if capturedAt.IsZero() {
				capturedAt = time.Now()
			}

			key, isFwd, payloadLen, isSYN, isACK, valid := decodePacket(packet)
			if !valid {
				continue
			}
			tracker.AddPacket(key, isFwd, payloadLen, isSYN, isACK, capturedAt)

		// ---- Flow expiry tick --------------------------------------------
		case now := <-ticker.C:
			expired := tracker.Expire(now)
			if len(expired) == 0 {
				continue
			}

			payloads := make([]FlowPayload, 0, len(expired))
			for _, fr := range expired {
				// Filter out trivial 1-packet flows (noise)
				if fr.FwdPkts+fr.BwdPkts < 2 {
					continue
				}
				payloads = append(payloads, fr.ToPayload())
			}

			if len(payloads) > 0 {
				if err := publisher.PushBatch(payloads); err != nil {
					log.Printf("[sniffer] Redis push error: %v", err)
				} else {
					flowCount += int64(len(payloads))
					log.Printf("[sniffer] Pushed %d flow(s) | total_pkts=%d total_flows=%d",
						len(payloads), pktCount, flowCount)
				}
			}

		// ---- Graceful shutdown -------------------------------------------
		case sig := <-sigCh:
			log.Printf("[sniffer] Received %v — flushing remaining flows...", sig)
			goto shutdown
		}
	}

shutdown:
	// Flush all active flows accumulated in the current window
	remaining := tracker.FlushAll()
	var finalPayloads []FlowPayload
	for _, fr := range remaining {
		if fr.FwdPkts+fr.BwdPkts >= 2 {
			finalPayloads = append(finalPayloads, fr.ToPayload())
		}
	}
	if len(finalPayloads) > 0 {
		if err := publisher.PushBatch(finalPayloads); err != nil {
			log.Printf("[sniffer] Final flush error: %v", err)
		} else {
			log.Printf("[sniffer] Flushed %d remaining flow(s).", len(finalPayloads))
		}
	}
	log.Printf("[sniffer] Stopped. Captured packets: %d | Flows pushed: %d",
		pktCount, flowCount+int64(len(finalPayloads)))
}
