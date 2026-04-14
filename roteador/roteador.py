import time

from scapy.all import (
    IP,
    TCP,
    UDP,
    Raw,
    Ether,
    sniff,
    sendp,
    get_if_addr,
    get_if_hwaddr,
    get_if_list,
    getmacbyip,
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
alert_state = {}


def match_hping3_repeated_x_120(payload):
    return len(payload) == 120 and payload == (b"X" * 120)


PAYLOAD_SIGNATURES = (
    {
        "name": "hping3_repeated_x_120",
        "reason": "payload corresponde a assinatura do hping3",
        "matcher": match_hping3_repeated_x_120,
    },
)


def extract_payload(pkt):
    if not pkt.haslayer(Raw):
        return b""
    return bytes(pkt[Raw].load)


def classify_payload(payload):
    for signature in PAYLOAD_SIGNATURES:
        if signature["matcher"](payload):
            return True, signature["name"], signature["reason"]
    return False, None, None


def format_endpoint(pkt):
    endpoint = pkt[IP].src if pkt.haslayer(IP) else "desconhecido"
    if pkt.haslayer(TCP):
        return f"{endpoint}:{pkt[TCP].sport}"
    if pkt.haslayer(UDP):
        return f"{endpoint}:{pkt[UDP].sport}"
    return endpoint


def format_destination(pkt):
    endpoint = pkt[IP].dst if pkt.haslayer(IP) else "desconhecido"
    if pkt.haslayer(TCP):
        return f"{endpoint}:{pkt[TCP].dport}"
    if pkt.haslayer(UDP):
        return f"{endpoint}:{pkt[UDP].dport}"
    return endpoint


def alert_aggregation_key(pkt, signature_name):
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if pkt.haslayer(TCP):
        return ("TCP", src_ip, dst_ip, pkt[TCP].dport, signature_name)
    if pkt.haslayer(UDP):
        return ("UDP", src_ip, dst_ip, pkt[UDP].dport, signature_name)
    return ("IP", src_ip, dst_ip, signature_name)


def format_alert_message(src, dst, signature_name, reason, blocked_count):
    return (
        f"[ALERTA] origem={src} destino={dst} "
        f"assinatura={signature_name} "
        f"motivo={reason} "
        f"pacotes_bloqueados={blocked_count} "
        f"janela_s={ALERT_AGGREGATION_WINDOW_SECONDS}"
    )


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
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    if pkt[Ether].src in [MAC_A, MAC_B]:
        return

    dst_ip = pkt[IP].dst
    if dst_ip.startswith("10.0.1."):
        out_iface = IFACE_A
        mac_origem = MAC_A
    elif dst_ip.startswith("10.0.2."):
        out_iface = IFACE_B
        mac_origem = MAC_B
    else:
        return

    mac_destino = cache_mac.get(dst_ip) or getmacbyip(dst_ip)
    if not mac_destino:
        return
    cache_mac[dst_ip] = mac_destino

    payload = extract_payload(pkt)
    is_malicious, signature_name, reason = classify_payload(payload)
    if payload and is_malicious:
        log_blocked_packet(pkt, signature_name, reason)
        return

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
sniff(iface=[IFACE_A, IFACE_B], filter="ip", prn=forward_packet, store=0)
