import os
import pickle
import socket
import sys
import traceback
from datetime import datetime
from pathlib import Path
from random import choice

from Tree.ProtoTree import ProtoTree
from format_inference_runtime import infer_protocol_groups_with_sender
from mutate import mutate2


# Public-release configuration.
# Replace TARGET_PLC_IP with the IP address of the Siemens PLC under test.
TARGET_PLC_IP = "REPLACE_WITH_SIEMENS_PLC_IP"
TARGET_PLC_PORT = 102

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


class S7PLCSender:
    def __init__(self, plc_ip, plc_port, timeout=5.0):
        self.plc_ip = plc_ip
        self.plc_port = plc_port
        self.timeout = timeout
        self.sock = None
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.plc_ip, self.plc_port))
            self.send_cotp_cr_packet()
            self.send_s7comm_init_packet()
            print(f"Connected to Siemens PLC {self.plc_ip}:{self.plc_port}")
            return True
        except Exception as exc:
            print(f"Failed to connect to Siemens PLC: {exc}")
            self.sock = None
            return False

    def reconnect(self):
        print("Reconnecting to Siemens PLC...")
        self.close()
        return self.connect()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_cotp_cr_packet(self):
        packet = (
            b"\x03\x00\x00\x16"
            b"\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
        )
        self.sock.send(packet)
        return self.sock.recv(1024)

    def send_s7comm_init_packet(self):
        packet = (
            b"\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00"
            b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
        )
        self.sock.send(packet)
        return self.sock.recv(1024)

    def send_raw_simple(self, packet_data: bytes):
        if not self.sock and not self.reconnect():
            return None

        try:
            self.sock.send(packet_data)
            return self.sock.recv(1024)
        except socket.timeout:
            self.reconnect()
            return None
        except (ConnectionAbortedError, ConnectionResetError, OSError):
            self.reconnect()
            return None


def ensure_output_dirs():
    CRASH_LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)


def split_seed(seed_bytes):
    if PAYLOAD_OFFSET is None:
        raise RuntimeError(
            "Please set PAYLOAD_OFFSET in siemens_fuzz.py. "
            "This value should point to the first byte after the function-code region."
        )
    if len(seed_bytes) <= PAYLOAD_OFFSET:
        return seed_bytes, b""
    return seed_bytes[:PAYLOAD_OFFSET], seed_bytes[PAYLOAD_OFFSET:]


def infer_seed_clusters():
    sender = S7PLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 5.0)
    try:
        inferred_clusters = []
        for seed in d_SEEDS:
            seed_bytes = bytes.fromhex(seed) if isinstance(seed, str) else seed
            prefix, payload = split_seed(seed_bytes)
            inferred_clusters.append(
                infer_protocol_groups_with_sender(
                    payload,
                    lambda fuzzed_payload, prefix=prefix: sender.send_raw_simple(prefix + fuzzed_payload),
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
    if TARGET_PLC_IP == "REPLACE_WITH_SIEMENS_PLC_IP":
        raise RuntimeError("Please set TARGET_PLC_IP in siemens_fuzz.py before running the public release.")

    d_SEEDS = [
        b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x01\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x82\x00\x00\x00",
        b"\x03\x00\x00\x2d\x02\xf0\x80\x32\x01\x00\x00\x02\x00\x00\x0e\x00\x0e\x05\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x82\x00\x00\x00\x00\x04\x00\x50\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
        b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x03\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x81\x00\x00\x00",
        b"\x03\x00\x00\x2d\x02\xf0\x80\x32\x01\x00\x00\x04\x00\x00\x0e\x00\x0e\x05\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x81\x00\x00\x00\x00\x04\x00\x50\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
        b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x05\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x83\x00\x00\x00",
        b"\x03\x00\x00\x2d\x02\xf0\x80\x32\x01\x00\x00\x06\x00\x00\x0e\x00\x0e\x05\x01\x12\x0a\x10\x02\x00\x0a\x00\x00\x83\x00\x00\x00\x00\x04\x00\x50\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
        b"\x03\x00\x00\x27\x02\xf0\x80\x32\x01\x00\x00\x0d\x00\x00\x0e\x00\x08\x05\x01\x12\x0a\x10\x1c\x00\x02\x00\x00\x1c\x00\x00\x00\x00\x09\x00\x04\x01\x02\x03\x04",
        b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x0e\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x1d\x00\x02\x00\x00\x1d\x00\x00\x00",
        b"\x03\x00\x00\x27\x02\xf0\x80\x32\x01\x00\x00\x0f\x00\x00\x0e\x00\x08\x05\x01\x12\x0a\x10\x1d\x00\x02\x00\x00\x1d\x00\x00\x00\x00\x09\x00\x04\x01\x02\x03\x04",
        b"\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x10\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x0a\x00\x01\x84\x00\x00\x00",
        b"\x03\x00\x00\x2d\x02\xf0\x80\x32\x01\x00\x00\x11\x00\x00\x0e\x00\x0e\x05\x01\x12\x0a\x10\x02\x00\x0a\x00\x01\x84\x00\x00\x00\x00\x04\x00\x50\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    ]

    CLUSTER.extend(infer_seed_clusters())
    print("Inferred byte groups for Siemens seeds:")
    for seed_index, byte_groups in enumerate(CLUSTER):
        print(f"seed[{seed_index}] -> {byte_groups}")
    SEED_ORIGIN.update(
        {
            (bytes.fromhex(seed)[0] if isinstance(seed, str) else seed[0]): idx
            for idx, seed in enumerate(d_SEEDS)
            if (bytes.fromhex(seed) if isinstance(seed, str) else seed)
        }
    )

    sender = S7PLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 5.0)
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
                    if not havoc_SEEDS:
                        continue

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

            except (ConnectionAbortedError, OSError):
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
