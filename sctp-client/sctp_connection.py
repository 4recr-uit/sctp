import sys
from ipaddress import IPv4Address


def connect_client(client, host, ethernet_ip, wifi_ip):
    multihoming = bool(ethernet_ip or wifi_ip)
    if multihoming:
        if not ethernet_ip or not wifi_ip:
            raise ValueError("Set both ETHERNET_IP and WIFI_IP to enable multihoming.")
        local_ips = IPv4Address(ethernet_ip), IPv4Address(wifi_ip)
        if local_ips[0] == local_ips[1]:
            raise ValueError("ETHERNET_IP and WIFI_IP must be distinct.")
        if any(ip.is_unspecified or ip.is_loopback or ip.is_multicast for ip in local_ips):
            raise ValueError("Use unicast IPv4 addresses assigned to the interfaces.")
        client.bindx([(str(ip), 0) for ip in local_ips])

    client.connect((host, 9899))

    if multihoming:
        print(f"SCTP local addresses: {client.getladdrs()}", file=sys.stderr)
        print(f"SCTP peer addresses: {client.getpaddrs()}", file=sys.stderr)
