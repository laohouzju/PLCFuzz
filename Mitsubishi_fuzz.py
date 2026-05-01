import binascii
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
# Replace TARGET_PLC_IP with the IP address of the Mitsubishi PLC under test.
TARGET_PLC_IP = "REPLACE_WITH_MITSUBISHI_PLC_IP"
TARGET_PLC_PORT = 5006

CRASH_LOG_DIR = Path("logs")
RESULT_DIR = Path("results")
# Replace PAYLOAD_OFFSET with the byte index immediately after the function code.
PAYLOAD_OFFSET = None
# Replace RESPONSE_OFFSET with the first response byte that should be added to the protocol tree.
RESPONSE_OFFSET = None

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


class MitsubishiPLCSender:
    def __init__(self, plc_ip, plc_port, timeout=2.0):
        self.plc_ip = plc_ip
        self.plc_port = plc_port
        self.timeout = timeout
        self.sock = None
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            print(f"Connected to Mitsubishi PLC {self.plc_ip}:{self.plc_port} over UDP")
            return True
        except Exception as exc:
            print(f"Failed to create UDP socket: {exc}")
            self.sock = None
            return False

    def reconnect(self):
        print("Reconnecting to Mitsubishi PLC...")
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

    def send_raw_simple(self, payload: bytes):
        if not self.sock and not self.reconnect():
            return None

        try:
            self.sock.sendto(payload, (self.plc_ip, self.plc_port))
            response, addr = self.sock.recvfrom(1024)
            return response
        except socket.timeout:
            return None
        except (ConnectionAbortedError, ConnectionResetError, OSError):
            self.reconnect()
            return self.send_raw_simple(payload)


def ensure_output_dirs():
    CRASH_LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)


def normalize_response(raw_response):
    if RESPONSE_OFFSET is None:
        raise RuntimeError(
            "Please set RESPONSE_OFFSET in Mitsubishi_fuzz.py. "
            "This value should point to the first response byte used for protocol-tree analysis."
        )
    if not raw_response:
        return b""
    return raw_response[RESPONSE_OFFSET:]


def split_seed(seed_bytes):
    if PAYLOAD_OFFSET is None:
        raise RuntimeError(
            "Please set PAYLOAD_OFFSET in Mitsubishi_fuzz.py. "
            "This value should point to the first byte after the function-code region."
        )
    if len(seed_bytes) <= PAYLOAD_OFFSET:
        return seed_bytes, b""
    return seed_bytes[:PAYLOAD_OFFSET], seed_bytes[PAYLOAD_OFFSET:]


def infer_seed_clusters():
    sender = MitsubishiPLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 2.0)
    try:
        inferred_clusters = []
        for seed in d_SEEDS:
            seed_bytes = bytes.fromhex(seed) if isinstance(seed, str) else seed
            prefix, payload = split_seed(seed_bytes)
            inferred_clusters.append(
                infer_protocol_groups_with_sender(
                    payload,
                    lambda fuzzed_payload, prefix=prefix: normalize_response(
                        sender.send_raw_simple(prefix + fuzzed_payload)
                    ),
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
    if TARGET_PLC_IP == "REPLACE_WITH_MITSUBISHI_PLC_IP":
        raise RuntimeError("Please set TARGET_PLC_IP in Mitsubishi_fuzz.py before running the public release.")

    mc_payloads = [
        binascii.a2b_hex("57012900001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008332c000000000000000000000000000000"),
        binascii.a2b_hex("5701f800001111070000ffff030000fe0300002a001c0a161400000000000000040000000000000000000000000833fb000000000000000000000000000000"),
        binascii.a2b_hex("5701da00001111070000ffff030000fe0300002a001c0a161400000000000000040000000000000000000000000833de000000000000000000000000000000"),
        binascii.a2b_hex("5701e400001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083304000000000000000000000000000100"),
        binascii.a2b_hex("57010e00001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008332f000000000000000000000000000100"),
        binascii.a2b_hex("5701ac00001111070000ffff030000fe0300002a001c0a161400000000000000040000000000000000000000000833cd000000000000000000000000000100"),
        binascii.a2b_hex("5701bf00001111070000ffff030000fe0300002a001c0a161400000000000000040000000000000000000000000833c3000000000000000000000000000200"),
        binascii.a2b_hex("57015400001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083359000000000000000000000000000200"),
        binascii.a2b_hex("57015000001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083356000000000000000000000000000200"),
        binascii.a2b_hex("57018700001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083388000000000000000000000000000200"),
        binascii.a2b_hex("57019000001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083392000000000000000000000000000200"),
        binascii.a2b_hex("57015000001111070000ffff030000fe0300002a001c0a16140000000000000004000000000000000000000000083353000000000000000000000000000200"),
        binascii.a2b_hex("57013900001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008333a000000000000000000000000000100"),
        binascii.a2b_hex("57015d00001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008335e000000000000000000000000000100"),
        binascii.a2b_hex("57014d00001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008334e000000000000000000000000000100"),
        binascii.a2b_hex("57015a00001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008335b000000000000000000000000000100"),
        binascii.a2b_hex("57015900001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008335a000000000000000000000000000100"),
        binascii.a2b_hex("57016a00001111070000ffff030000fe0300002a001c0a1614000000000000000400000000000000000000000008336b000000000000000000000000000100")
    ]
    d_SEEDS = [payload.hex() for payload in mc_payloads]

    CLUSTER.extend(infer_seed_clusters())
    print("Inferred byte groups for Mitsubishi seeds:")
    for seed_index, byte_groups in enumerate(CLUSTER):
        print(f"seed[{seed_index}] -> {byte_groups}")
    SEED_ORIGIN.update(
        {
            (bytes.fromhex(seed)[0] if isinstance(seed, str) else seed[0]): idx
            for idx, seed in enumerate(d_SEEDS)
            if (bytes.fromhex(seed) if isinstance(seed, str) else seed)
        }
    )

    sender = MitsubishiPLCSender(TARGET_PLC_IP, TARGET_PLC_PORT, 2.0)
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
                        resp = normalize_response(ori_resp)
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
                resp = normalize_response(ori_resp)
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
