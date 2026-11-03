#!/usr/bin/env python3
import argparse
import os
import socket
import time

parser = argparse.ArgumentParser()
parser.add_argument("--resolver", default="10.20.10.50", help="DNS server IP")
args = parser.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print(f"[*] Đang gửi 60 truy vấn DNS giả lập tới {args.resolver}:53...")
for i in range(60):
    sub = f"test-{i}-{os.urandom(3).hex()}".encode()
    query = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes([len(sub)]) + sub + b"\x09hicp-demo\x07invalid\x00\x00\x01\x00\x01"
    s.sendto(query, (args.resolver, 53))
    time.sleep(0.2)

print("[+] Hoàn tất gửi 60 truy vấn DNS giả lập!")