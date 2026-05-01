import os
import pickle
import socket
import struct
import sys
import traceback
from datetime import datetime
from pathlib import Path
from random import choice

from Tree.ProtoTree import ProtoTree
from mutate import mutate2
from format_inference_runtime import infer_protocol_groups_with_sender


# Public-release configuration.
# Replace TARGET_PLC_IP with the IP address of the Delta PLC under test.
TARGET_PLC_IP = "REPLACE_WITH_DELTA_PLC_IP"
TARGET_PLC_PORT = 502

# Replace PACKET_FILE with a text file that contains one packet per line.
PACKET_FILE = "REPLACE_WITH_DELTA_PACKET_FILE"

CRASH_LOG_DIR = Path("logs")
RESULT_DIR = Path("results")
# Replace PAYLOAD_OFFSET with the byte index immediately after the function code.
PAYLOAD_OFFSET = None

d_SEEDS = []
CLUSTER = []
havoc_SEEDS = []
crash_SEEDS = []
UNEXPECTED_PAIRS = {}
SEED_ORIGIN = {}

testcase_num = 0
MAINTENANCE_COUNTER = 0
DERTERMINED_NUM = 0
HAVOC_NUM = 0
unique_path_num = 0


class DeltaPLCSender:
    def __init__(self, plc_ip, plc_port, timeout=8.0):
        self.plc_ip = plc_ip
        self.plc_port = plc_port
        self.timeout = timeout
        self.sock = None
        self.transaction_id = 0
        self.protocol_id = 0
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.plc_ip, self.plc_port))
            print(f"Connected to Delta PLC {self.plc_ip}:{self.plc_port}")
            return True
        except Exception as exc:
            print(f"Failed to connect to Delta PLC: {exc}")
            self.sock = None
            return False

    def reconnect(self):
        print("Reconnecting to Delta PLC...")
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        return self.connect()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def extract_modbus_payload(self, packet_data: bytes) -> bytes:
        if len(packet_data) < 60:
            return packet_data

        try:
            ip_version = (packet_data[14] & 0xF0) >> 4
            if ip_version != 4:
                return packet_data

            ip_header_length = (packet_data[14] & 0x0F) * 4
            tcp_data_offset = (packet_data[14 + ip_header_length + 12] & 0xF0) >> 4
            tcp_header_length = tcp_data_offset * 4
            tcp_header_start = 14 + ip_header_length
            modbus_data_start = tcp_header_start + tcp_header_length
            return packet_data[modbus_data_start:]
        except Exception:
            return packet_data

    def send_raw_simple(self, payload: bytes):
        if not self.sock and not self.reconnect():
            return None

        try:
            modbus_payload = self.extract_modbus_payload(payload)

            if len(modbus_payload) >= 6 and modbus_payload[2:4] == b"\x00\x00":
                self.sock.send(modbus_payload)
            else:
                self.transaction_id = (self.transaction_id + 1) % 65536
                length = len(modbus_payload) + 1
                mbap_header = struct.pack(">HHH", self.transaction_id, self.protocol_id, length)
                modbus_tcp_message = mbap_header + b"\x00" + modbus_payload
                self.sock.send(modbus_tcp_message)

            response_header = self.sock.recv(6)
            if len(response_header) < 6:
                return b""

            _, _, length = struct.unpack(">HHH", response_header)
            response_data = self.sock.recv(length)
            return response_header + response_data
        except (ConnectionAbortedError, ConnectionResetError, socket.timeout, OSError):
            self.reconnect()
            return self.send_raw_simple(payload)


def ensure_output_dirs():
    CRASH_LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)


def load_packets_from_file(file_path=PACKET_FILE):
    packets = []
    if file_path == "REPLACE_WITH_DELTA_PACKET_FILE":
        return packets

    with open(file_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                packets.append(line)
    return packets


def split_seed(seed_bytes):
    if PAYLOAD_OFFSET is None:
        raise RuntimeError(
            "Please set PAYLOAD_OFFSET in delta_fuzz.py. "
            "This value should point to the first byte after the function-code region."
        )
    if len(seed_bytes) <= PAYLOAD_OFFSET:
        return seed_bytes, b""
    return seed_bytes[:PAYLOAD_OFFSET], seed_bytes[PAYLOAD_OFFSET:]


def infer_seed_clusters():
    sender = DeltaPLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 8.0)
    try:
        inferred_clusters = []
        for seed in d_SEEDS:
            seed_bytes = bytes.fromhex(seed) if isinstance(seed, str) else seed
            _, payload = split_seed(seed_bytes)
            inferred_clusters.append(
                infer_protocol_groups_with_sender(
                    payload,
                    lambda fuzzed_payload, prefix=seed_bytes[:PAYLOAD_OFFSET]: sender.send_raw_simple(prefix + fuzzed_payload),
                )
            )
        return inferred_clusters
    finally:
        sender.close()


def d_mutate(prefix, default_value, sender, cluster):
    global testcase_num
    for payload, locate in mutate2.determined_mutate(default_value, cluster):
        fuzz_seed = prefix + payload
        if fuzz_seed not in crash_SEEDS:
            resp = sender.send_raw_simple(fuzz_seed)
            testcase_num += 1
            yield fuzz_seed, resp, locate


def havoc_by_cluster(seed_bytes, cluster):
    prefix, payload = split_seed(seed_bytes)
    if not payload:
        mutated_payload, tag = mutate2.havoc(seed_bytes)
        return mutated_payload, tag

    if not cluster:
        mutated_payload, tag = mutate2.havoc(payload)
        return prefix + mutated_payload, tag

    target_group = choice(cluster)
    group_bytes = bytes(payload[index] for index in target_group)
    mutated_group, tag = mutate2.havoc(group_bytes)
    new_payload = bytearray(payload)
    for offset, index in enumerate(target_group):
        if offset < len(mutated_group):
            new_payload[index] = mutated_group[offset]
    return prefix + bytes(new_payload), tag


def tree_maintenance(tree: ProtoTree, root: ProtoTree.Node):
    global MAINTENANCE_COUNTER
    global havoc_SEEDS

    MAINTENANCE_COUNTER += 1
    merge_threshold = 300
    old_len = len(tree)
    old_seed = len(havoc_SEEDS)

    for p in tree.preorder(root):
        children = tree.children(p)
        child_num = 0
        for child in children:
            child_num += len(child.element_pair)
            if child.is_merged:
                child_num = len(child.element_pair)
                break
        score = child_num + 3 * tree.depth(p)
        if score >= 120:
            tree.cut(p)
        elif len(children) >= 2 and child_num >= merge_threshold:
            tree.merge(children[0], *children[1:])

    havoc_SEEDS = []
    for p in tree.breadthfirst(root):
        if tree.is_leaf(p) and p.unique_seed:
            havoc_SEEDS.append(choice(p.unique_seed))

    os.system("cls")
    print(f"maintenance counter: {MAINTENANCE_COUNTER}")
    children_map = tree.list_children(root)
    if children_map:
        for element, count in children_map.items():
            print(element, count)
    print(f"tree size : {old_len} -> {len(tree)}")
    print(f"seed num : {old_seed} -> {len(havoc_SEEDS)}")
    print(f"determined seeds : {len(d_SEEDS)}")
    print(f"determined num : {DERTERMINED_NUM}")
    print(f"havoc num : {HAVOC_NUM}")


if __name__ == "__main__":
    crash_count = 0
    sys.setrecursionlimit(10000000)
    start_time = datetime.now()
    os.system("cls")

    ensure_output_dirs()
    if TARGET_PLC_IP == "REPLACE_WITH_DELTA_PLC_IP":
        raise RuntimeError("Please set TARGET_PLC_IP in delta_fuzz.py before running the public release.")

    d_SEEDS = load_packets_from_file()
    if not d_SEEDS:
        d_SEEDS = [
            b"\x42\xe2\x00\x06\x00\x01\x00\x01\x00\x06",
            b"\x42\x2a\x00\x04\x00\x01\x10\x01",
            b"\x67\x00\x10\x00\x05",
            b"\x42\x02\x00\x06\x00\x00\x00\x64\x00\x01",
            b"\x67\x00\x10\x00\x05"
        ]

    CLUSTER.extend(infer_seed_clusters())
    print("Inferred byte groups for Delta seeds:")
    for seed_index, byte_groups in enumerate(CLUSTER):
        print(f"seed[{seed_index}] -> {byte_groups}")
    SEED_ORIGIN.update(
        {
            (bytes.fromhex(seed)[0] if isinstance(seed, str) else seed[0]): idx
            for idx, seed in enumerate(d_SEEDS)
            if (bytes.fromhex(seed) if isinstance(seed, str) else seed)
        }
    )

    sender = DeltaPLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 8.0)
    ptree = ProtoTree()
    hroot = ptree.add_root("ROOT")

    try:
        while True:
            try:
                if HAVOC_NUM >= 5000:
                    tree_maintenance(ptree, hroot)
                    print("state : havoc")
                    HAVOC_NUM = 0

                for seed in d_SEEDS:
                    seed_bytes = bytes.fromhex(seed) if isinstance(seed, str) else seed
                    prefix, payload = split_seed(seed_bytes)
                    cluster = CLUSTER[d_SEEDS.index(seed)] if d_SEEDS.index(seed) < len(CLUSTER) else []
                    if DERTERMINED_NUM >= 5000:
                        tree_maintenance(ptree, hroot)
                        print("state : determined mutation")
                        DERTERMINED_NUM = 0
                    for fuzz_seed, ori_resp, fuzz_locate in d_mutate(prefix, payload, sender, cluster):
                        resp = ori_resp or b""
                        if resp:
                            DERTERMINED_NUM += 1
                            ptree.add_packet(resp, fuzz_seed)
                d_SEEDS = []

                if not havoc_SEEDS:
                    tree_maintenance(ptree, hroot)
                    print("state : start")
                    DERTERMINED_NUM, HAVOC_NUM = 0, 0
                seed = choice(havoc_SEEDS)
                seed_bytes = bytes.fromhex(seed) if isinstance(seed, str) else seed
                cluster_index = SEED_ORIGIN.get(seed_bytes[0], 0) if seed_bytes else 0
                cluster = CLUSTER[cluster_index] if cluster_index < len(CLUSTER) else []
                fuzz_seed, tag = havoc_by_cluster(seed_bytes, cluster)
                if fuzz_seed not in crash_SEEDS:
                    ori_resp = sender.send_raw_simple(fuzz_seed)
                    testcase_num += 1
                resp = ori_resp or b""
                if resp:
                    HAVOC_NUM += 1
                    newpath = ptree.add_packet(resp, fuzz_seed)
                    if newpath:
                        d_SEEDS.append(fuzz_seed)
                        unique_path_num += 1

            except ConnectionAbortedError:
                time_cost = (datetime.now() - start_time).seconds
                hours = time_cost // 3600
                minutes = (time_cost - hours * 3600) // 60
                seconds = time_cost - hours * 3600 - minutes * 60
                print(f"time cost : {hours}:{minutes}:{seconds}")
                with (CRASH_LOG_DIR / "deltatime.txt").open("a", encoding="utf-8") as f0:
                    print(f"time cost : {hours}:{minutes}:{seconds}", file=f0)
                print("\nconnection aborted")
                crash_count += 1
                with (CRASH_LOG_DIR / "deltacrashcount.txt").open("a", encoding="utf-8") as f1:
                    print(f"crash_count : {crash_count}", file=f1)
                crash_SEEDS.append(fuzz_seed)
                with (CRASH_LOG_DIR / "deltacrashseed.txt").open("a", encoding="utf-8") as f2:
                    print(f"crash_seed : {fuzz_seed}", file=f2)
                if MAINTENANCE_COUNTER == 0:
                    tree_maintenance(ptree, hroot)
                    d_SEEDS = []
                sender.reconnect()

            except OSError:
                time_cost = (datetime.now() - start_time).seconds
                hours = time_cost // 3600
                minutes = (time_cost - hours * 3600) // 60
                seconds = time_cost - hours * 3600 - minutes * 60
                print(f"time cost : {hours}:{minutes}:{seconds}")
                print("\nconnection aborted")
                crash_count += 1
                crash_SEEDS.append(fuzz_seed)
                if MAINTENANCE_COUNTER == 0:
                    tree_maintenance(ptree, hroot)
                    d_SEEDS = []
                sender.reconnect()

    except KeyboardInterrupt:
        print("\nkeyboard interrupt by user")
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        print(f"\nUnexpected error : {exc_type}")
        print(exc_value)
        traceback.print_tb(exc_tb)
    finally:
        sender.close()
        print("saving data")
        with (RESULT_DIR / "unexpected_pairs.pickle").open("wb") as handle:
            pickle.dump(UNEXPECTED_PAIRS, handle, pickle.HIGHEST_PROTOCOL)
        with (RESULT_DIR / "fuzztree.pickle").open("wb") as handle:
            pickle.dump(ptree, handle, pickle.HIGHEST_PROTOCOL)

        count = 0
        for node in ptree.preorder(hroot):
            if node.is_merged:
                count += 1
        print(f"merged node : {count}")
        time_cost = (datetime.now() - start_time).seconds
        hours = time_cost // 3600
        minutes = (time_cost - hours * 3600) // 60
        seconds = time_cost - hours * 3600 - minutes * 60
        print(f"time cost : {hours}:{minutes}:{seconds}")
        print(f"crash_count = {crash_count}")
        print(f"unique_path = {unique_path_num}")
        print(f"testcase_num = {testcase_num}")
