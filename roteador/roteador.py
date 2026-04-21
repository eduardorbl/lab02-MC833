import csv
import hashlib
import time
from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    get_if_addr,
    get_if_hwaddr,
    get_if_list,
    getmacbyip,
    sendp,
    sniff,
)


def resolve_iface_by_ip(expected_ip):
    for iface in get_if_list():
        try:
            if get_if_addr(iface) == expected_ip:
                return iface
        except OSError:
            continue
    raise RuntimeError(f"Interface com IP {expected_ip} nao encontrada")


IFACE_A = resolve_iface_by_ip("10.0.1.254")  # Rede A
IFACE_B = resolve_iface_by_ip("10.0.2.254")  # Rede B

MAC_A = get_if_hwaddr(IFACE_A)
MAC_B = get_if_hwaddr(IFACE_B)

cache_mac = {}

ALERT_AGGREGATION_WINDOW_SECONDS = 5
PAYLOAD_BURST_WINDOW_SECONDS = 1.0
PAYLOAD_BURST_THRESHOLD = 5
MAX_PAYLOAD_EXAMPLES_PER_WINDOW = 5

alert_state = {}
payload_burst_state = {}

STATS_WINDOW_SECONDS = 5
CLIENT_IP = "10.0.2.2"
SERVER_IP = "10.0.1.2"
DATA_FILE_PATH = Path(__file__).resolve().with_name("data.csv")
CAPTURE_STARTED_AT = time.monotonic()
stats_state = {}

CSV_FIELDS = (
    "flow_id",
    "time_sec",
    "total_packages",
    "total_bytes",
    "bps",
    "pps",
    "window_start_sec",
    "window_end_sec",
    "window_duration_s",
    "protocol",
    "service",
    "direction",
    "traffic_class",
    "decision",
    "signature_name",
    "payload_textual_packets",
    "payload_binary_packets",
    "payload_empty_packets",
    "payload_markers",
    "payload_examples",
)

SERVICE_PORTS = {
    80: "nginx",
    23: "telnet",
    3306: "mariadb",
}


def extract_payload(pkt):
    if not pkt.haslayer(Raw):
        return b""
    return bytes(pkt[Raw].load)


def decode_payload_text(payload):
    if not payload:
        return None

    # Repeticao de um unico byte e um forte indicio de payload sintetico.
    if len(payload) >= 16 and len(set(payload)) == 1:
        return None

    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None

    allowed_control_chars = {"\n", "\r", "\t"}
    if any((not char.isprintable()) and char not in allowed_control_chars for char in decoded):
        return None

    return decoded


def format_payload_preview(text, limit=60):
    compact = text.replace("\r", "\\r").replace("\n", "\\n").strip()
    return compact[:limit]


def get_transport_details(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP], "TCP", pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP], "UDP", pkt[UDP].sport, pkt[UDP].dport
    return None, "IP", None, None


def collect_textual_markers(lowered_text):
    markers = set()
    if lowered_text.startswith("get "):
        markers.add("http_get")
    if "aluno" in lowered_text:
        markers.add("telnet_username_aluno")
    if "lab123" in lowered_text:
        markers.add("telnet_password_lab123")
    if "ls -la" in lowered_text:
        markers.add("telnet_command_ls")
    return markers


def observe_payload(payload):
    if not payload:
        return {
            "payload": b"",
            "kind": "empty",
            "markers": tuple(),
            "examples": tuple(),
            "fingerprint": "",
            "unique_byte_count": 0,
        }

    markers = set()
    examples = []
    unique_byte_count = len(set(payload))
    decoded_text = decode_payload_text(payload)

    if unique_byte_count == 1 and payload[:1] == b"X":
        markers.add("binary_repeated_x")

    if unique_byte_count <= 2 and len(payload) >= 16:
        markers.add("low_entropy_payload")

    if decoded_text is not None:
        lowered = decoded_text.lower()
        markers.update(collect_textual_markers(lowered))

        example = format_payload_preview(decoded_text)
        if example:
            examples.append(example)
        kind = "textual"
    else:
        kind = "binary"

    return {
        "payload": payload,
        "kind": kind,
        "markers": tuple(sorted(markers)),
        "examples": tuple(examples),
        "fingerprint": hashlib.sha1(payload).hexdigest(),
        "unique_byte_count": unique_byte_count,
    }


def prune_payload_burst_state(now):
    for key, state in list(payload_burst_state.items()):
        if now - state["last_seen_at"] > PAYLOAD_BURST_WINDOW_SECONDS:
            payload_burst_state.pop(key, None)


def register_payload_burst(signature_name, fingerprint, now):
    prune_payload_burst_state(now)
    key = (signature_name, fingerprint)
    state = payload_burst_state.get(key)

    if state is None or now - state["window_start"] > PAYLOAD_BURST_WINDOW_SECONDS:
        state = {"window_start": now, "last_seen_at": now, "count": 0}
        payload_burst_state[key] = state

    state["last_seen_at"] = now
    state["count"] += 1
    return state["count"]


def match_hping3_repeated_x_burst(pkt, payload_info, now):
    payload = payload_info["payload"]

    if not pkt.haslayer(TCP):
        return False, None
    if len(payload) != 120:
        return False, None
    if payload_info["unique_byte_count"] != 1 or payload[:1] != b"X":
        return False, None

    burst_count = register_payload_burst(
        "hping3_repeated_x_burst", payload_info["fingerprint"], now
    )
    if burst_count < PAYLOAD_BURST_THRESHOLD:
        return False, None

    return (
        True,
        (
            "payload repetitivo de 120 bytes com baixa entropia "
            f"observado em burst ({burst_count} ocorrencias em "
            f"{PAYLOAD_BURST_WINDOW_SECONDS:.1f}s)"
        ),
    )


PAYLOAD_SIGNATURES = (
    {
        "name": "hping3_repeated_x_burst",
        "matcher": match_hping3_repeated_x_burst,
    },
)


def classify_payload(pkt, payload_info, now):
    for signature in PAYLOAD_SIGNATURES:
        matched, reason = signature["matcher"](pkt, payload_info, now)
        if matched:
            return True, signature["name"], reason
    return False, None, None


def format_endpoint(pkt):
    endpoint = pkt[IP].src if pkt.haslayer(IP) else "desconhecido"
    _transport, _protocol, sport, _dport = get_transport_details(pkt)
    if sport is not None:
        return f"{endpoint}:{sport}"
    return endpoint


def format_destination(pkt):
    endpoint = pkt[IP].dst if pkt.haslayer(IP) else "desconhecido"
    _transport, _protocol, _sport, dport = get_transport_details(pkt)
    if dport is not None:
        return f"{endpoint}:{dport}"
    return endpoint


def alert_aggregation_key(pkt, signature_name):
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    _transport, protocol, _sport, dport = get_transport_details(pkt)
    if dport is not None:
        return (protocol, src_ip, dst_ip, dport, signature_name)
    return ("IP", src_ip, dst_ip, signature_name)


def format_alert_message(src, dst, signature_name, reason, blocked_count):
    return (
        f"[ALERTA] origem={src} destino={dst} "
        f"assinatura={signature_name} "
        f"motivo={reason} "
        f"pacotes_bloqueados={blocked_count} "
        f"janela_s={ALERT_AGGREGATION_WINDOW_SECONDS}"
    )


def write_csv_header():
    with DATA_FILE_PATH.open("w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()


def ensure_data_file():
    if not DATA_FILE_PATH.exists():
        write_csv_header()
        return

    with DATA_FILE_PATH.open("r", newline="") as csv_file:
        current_header = csv_file.readline().strip()

    expected_header = ",".join(CSV_FIELDS)
    if current_header == expected_header:
        return

    backup_path = DATA_FILE_PATH.with_name(
        f"{DATA_FILE_PATH.stem}.legacy.{int(time.time())}{DATA_FILE_PATH.suffix}"
    )
    DATA_FILE_PATH.replace(backup_path)
    print(
        "[INFO] data.csv anterior movido para "
        f"{backup_path.name} por incompatibilidade de schema."
    )
    write_csv_header()


def resolve_service(pkt):
    transport, _protocol, sport, dport = get_transport_details(pkt)
    if transport is None:
        return "unknown"
    if dport in SERVICE_PORTS:
        return SERVICE_PORTS[dport]
    if sport in SERVICE_PORTS:
        return SERVICE_PORTS[sport]
    return "unknown"


def classify_traffic(pkt, is_malicious, signature_name):
    service = resolve_service(pkt)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    metadata = {
        "flow_id": f"other-{service}",
        "service": service,
        "direction": "other",
        "traffic_class": "normal",
        "decision": "forwarded",
        "signature_name": "",
    }

    if is_malicious:
        metadata.update(
            {
                "flow_id": f"attacker-{service}",
                "direction": "attacker_to_server",
                "traffic_class": "anomalous",
                "decision": "blocked",
                "signature_name": signature_name or "",
            }
        )
    elif src_ip == CLIENT_IP and dst_ip == SERVER_IP:
        metadata.update(
            {
                "flow_id": f"client-{service}",
                "direction": "client_to_server",
            }
        )
    elif src_ip == SERVER_IP and dst_ip == CLIENT_IP:
        metadata.update(
            {
                "flow_id": f"server-{service}",
                "direction": "server_to_client",
            }
        )

    return metadata


def get_metrics_key(protocol, metadata):
    return (
        metadata["flow_id"],
        protocol,
        metadata["service"],
        metadata["direction"],
        metadata["traffic_class"],
        metadata["decision"],
        metadata["signature_name"],
    )


def get_bucket_window(now):
    bucket_index = int((now - CAPTURE_STARTED_AT) // STATS_WINDOW_SECONDS)
    window_start = CAPTURE_STARTED_AT + (bucket_index * STATS_WINDOW_SECONDS)
    window_end = window_start + STATS_WINDOW_SECONDS
    return bucket_index, window_start, window_end


def flush_metrics_window(key, force=False, now=None):
    window = stats_state.pop(key, None)
    if window is None or window["total_packages"] == 0:
        return

    if force:
        reference_time = window["last_seen_at"] if now is None else min(now, window["window_end"])
        row_window_end = max(reference_time, window["window_start"] + 0.001)
        row_window_duration = max(row_window_end - window["window_start"], 0.001)
    else:
        row_window_end = window["window_end"]
        row_window_duration = STATS_WINDOW_SECONDS

    row = {
        "flow_id": window["flow_id"],
        "time_sec": round(row_window_end - CAPTURE_STARTED_AT, 3),
        "total_packages": window["total_packages"],
        "total_bytes": window["total_bytes"],
        "bps": round(window["total_bytes"] / row_window_duration, 3),
        "pps": round(window["total_packages"] / row_window_duration, 3),
        "window_start_sec": round(window["window_start"] - CAPTURE_STARTED_AT, 3),
        "window_end_sec": round(row_window_end - CAPTURE_STARTED_AT, 3),
        "window_duration_s": round(row_window_duration, 3),
        "protocol": window["protocol"],
        "service": window["service"],
        "direction": window["direction"],
        "traffic_class": window["traffic_class"],
        "decision": window["decision"],
        "signature_name": window["signature_name"],
        "payload_textual_packets": window["payload_textual_packets"],
        "payload_binary_packets": window["payload_binary_packets"],
        "payload_empty_packets": window["payload_empty_packets"],
        "payload_markers": "|".join(sorted(window["payload_markers"])),
        "payload_examples": " || ".join(window["payload_examples"]),
    }

    with DATA_FILE_PATH.open("a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writerow(row)


def flush_completed_windows(now):
    for key, window in list(stats_state.items()):
        if window["window_end"] <= now:
            flush_metrics_window(key)


def flush_all_metrics(now=None):
    reference_time = time.monotonic() if now is None else now
    for key in list(stats_state):
        flush_metrics_window(key, force=True, now=reference_time)


def record_payload_observation(window, payload_info):
    kind = payload_info["kind"]
    if kind == "textual":
        window["payload_textual_packets"] += 1
    elif kind == "binary":
        window["payload_binary_packets"] += 1
    else:
        window["payload_empty_packets"] += 1

    window["payload_markers"].update(payload_info["markers"])

    for example in payload_info["examples"]:
        if example in window["payload_examples"]:
            continue
        if len(window["payload_examples"]) >= MAX_PAYLOAD_EXAMPLES_PER_WINDOW:
            break
        window["payload_examples"].append(example)


def record_packet_metrics(pkt, is_malicious, signature_name, payload_info):
    ensure_data_file()

    now = time.monotonic()
    flush_completed_windows(now)

    _transport, protocol, _sport, _dport = get_transport_details(pkt)
    metadata = classify_traffic(pkt, is_malicious, signature_name)
    bucket_index, window_start, window_end = get_bucket_window(now)
    key = get_metrics_key(protocol, metadata) + (bucket_index,)
    packet_size = len(bytes(pkt[IP]))

    window = stats_state.get(key)
    if window is None:
        window = {
            "flow_id": metadata["flow_id"],
            "protocol": protocol,
            "service": metadata["service"],
            "direction": metadata["direction"],
            "traffic_class": metadata["traffic_class"],
            "decision": metadata["decision"],
            "signature_name": metadata["signature_name"],
            "window_start": window_start,
            "window_end": window_end,
            "last_seen_at": now,
            "total_packages": 0,
            "total_bytes": 0,
            "payload_textual_packets": 0,
            "payload_binary_packets": 0,
            "payload_empty_packets": 0,
            "payload_markers": set(),
            "payload_examples": [],
        }
        stats_state[key] = window

    window["last_seen_at"] = now
    window["total_packages"] += 1
    window["total_bytes"] += packet_size
    record_payload_observation(window, payload_info)


def log_blocked_packet(pkt, signature_name, reason):
    src = format_endpoint(pkt)
    dst = format_destination(pkt)
    key = alert_aggregation_key(pkt, signature_name)
    now = time.monotonic()
    state = alert_state.get(key)

    if state is None:
        print(format_alert_message(src, dst, signature_name, reason, 1))
        alert_state[key] = {"last_log_at": now, "suppressed_count": 0}
        return

    if now - state["last_log_at"] >= ALERT_AGGREGATION_WINDOW_SECONDS:
        blocked_count = state["suppressed_count"] + 1
        print(format_alert_message(src, dst, signature_name, reason, blocked_count))
        state["last_log_at"] = now
        state["suppressed_count"] = 0
        return

    state["suppressed_count"] += 1


def forward_packet(pkt):
    # 1. Verificacoes basicas
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    # 2. Evitar loops (nao processar o que o proprio roteador enviou)
    if pkt[Ether].src in [MAC_A, MAC_B]:
        return

    # 3. Determinar interface de saida e MAC de origem
    dst_ip = pkt[IP].dst
    if dst_ip.startswith("10.0.1."):
        out_iface = IFACE_A
        mac_origem = MAC_A
    elif dst_ip.startswith("10.0.2."):
        out_iface = IFACE_B
        mac_origem = MAC_B
    else:
        return

    # 4. Descobrir MAC de destino (quem deve receber o pacote na ponta final)
    mac_destino = cache_mac.get(dst_ip) or getmacbyip(dst_ip)
    if not mac_destino:
        return
    cache_mac[dst_ip] = mac_destino

    # 5. Inspecao de payload, decisao e registro de metricas
    now = time.monotonic()
    payload_info = observe_payload(extract_payload(pkt))
    is_malicious, signature_name, reason = classify_payload(pkt, payload_info, now)
    record_packet_metrics(pkt, is_malicious, signature_name, payload_info)
    if payload_info["payload"] and is_malicious:
        log_blocked_packet(pkt, signature_name, reason)
        return

    # 6. Preparacao do pacote para reenvio
    pkt[Ether].src = mac_origem
    pkt[Ether].dst = mac_destino

    if pkt[IP].ttl <= 1:
        return
    pkt[IP].ttl -= 1

    del pkt[IP].chksum
    if pkt.haslayer(TCP):
        del pkt[TCP].chksum
    elif pkt.haslayer(UDP):
        del pkt[UDP].chksum

    sendp(pkt, iface=out_iface, verbose=False)


print(f"Roteador Scapy Ativo (L2 Mode) em {IFACE_A=} e {IFACE_B=}...")
ensure_data_file()

try:
    sniff(iface=[IFACE_A, IFACE_B], filter="ip", prn=forward_packet, store=0)
finally:
    flush_all_metrics(now=time.monotonic())