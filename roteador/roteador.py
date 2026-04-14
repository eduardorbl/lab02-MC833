from scapy.all import (
    IP,
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

# Cache de MAC para não travar o roteador com requisições ARP lentas
cache_mac = {}


def extract_payload(pkt):
    if not pkt.haslayer(Raw):
        return b""
    return bytes(pkt[Raw].load)


def classify_payload(payload):
    if len(payload) == 120 and payload == (b"X" * 120):
        return True, "payload corresponde a assinatura do hping3"
    return False, None

def forward_packet(pkt):
    # 1. Verificações básicas
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    # 2. Evitar loops (não processar o que o próprio roteador enviou)
    if pkt[Ether].src in [MAC_A, MAC_B]:
        return

    # 3. Determinar interface de saída e MAC de origem
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

    # 5. Inspecionar payload e decidir se o pacote deve ser bloqueado.
    payload = extract_payload(pkt)
    is_malicious, reason = classify_payload(payload)
    if payload and is_malicious:
        print(
            f"[ALERTA] Dropando pacote {pkt[IP].src} -> {pkt[IP].dst}: "
            f"{reason}"
        )
        return

    # 6. PREPARAÇÃO DO PACOTE PARA REENVIO
    # Alteramos o cabeçalho Ethernet (L2) para o próximo salto
    pkt[Ether].src = mac_origem
    pkt[Ether].dst = mac_destino
    
    # Alteramos o IP (L3)
    pkt[IP].ttl -= 1
    
    # FORÇAR RECALCULO DE CHECKSUM (Crucial para MariaDB/Telnet)
    # Deletamos os campos antigos; o Scapy calcula os novos no sendp()
    del pkt[IP].chksum
    if pkt.haslayer('TCP'):
        del pkt['TCP'].chksum
    elif pkt.haslayer('UDP'):
        del pkt['UDP'].chksum

    # 7. ENVIAR VIA CAMADA 2
    sendp(pkt, iface=out_iface, verbose=False)

print(f"Roteador Scapy Ativo (L2 Mode) em {IFACE_A=} e {IFACE_B=}...")
sniff(iface=[IFACE_A, IFACE_B], prn=forward_packet, store=0)
