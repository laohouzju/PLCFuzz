import argparse
import csv
import socket
import time
from pathlib import Path

from Tree.ProtoTree import ProtoTree
from mutate import modiconInit


ALPHA = 0.8
# Replace this with the IP address of your target PLC before running.
DEFAULT_HOST = "REPLACE_WITH_TARGET_PLC_IP"
DEFAULT_PORT = 502
DEFAULT_TIMEOUT = 8.0
OUTPUT_CSV = "format_inference_results.csv"
PACKET_COUNT = 0


UMAS_SEEDS = [
    ("INIT_CONNECTION", b"\x01\x00"),
    ("READ_MEMORY_BLOCK", b"\x20\x01\x13\x00\x00\x00\x00\x00\x64\x64"),
    ("EXTRACT_PROTOCOL", b"\x22\x04\xe9\x0d\x02\x01\x02\x2b\x00\x01\x00\x00\xb8"),
    ("READ_VARIABLES", b"\x25\x01\x00\x03\x01\x00\x00\x00\x02\x00\x23\x23\x56\x32"),
    ("SESSION_INFO", b"\x29\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ("CHECK_STATUS", b"\x28\x00\x00\x00\x00\x00\x00"),
    ("READ_PLC_INFO", b"\x34\x00\x01\x01\x00"),
    ("MONITOR", b"\x41\xff\x00"),
    ("TAKE_RESERVATION", b"\x10\x25\x10\x00\x00\x05\x4f\x57\x4e\x44\x45"),
    ("PROJECT_QUERY", b"\x50\x15\x00\x01\x0b"),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Measure runtime of UMAS adjacent-byte format inference."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--protocol", default="all")
    parser.add_argument("--output", default=OUTPUT_CSV)
    return parser.parse_args()


def pick_protocols(protocol_name):
    if protocol_name.lower() == "all":
        return UMAS_SEEDS
    result = []
    for name, seed in UMAS_SEEDS:
        if name.lower() == protocol_name.lower():
            result.append((name, seed))
    if not result:
        raise ValueError(f"unknown protocol: {protocol_name}")
    return result


def mutate_seed(seed, indexes, values):
    fuzzed = bytearray(seed)
    for index, value in zip(indexes, values):
        fuzzed[index] = value & 0xFF
    return bytes(fuzzed)


def normalize_response(raw_response):
    if not raw_response:
        return b""
    return raw_response[9:]


def connect_target(host, port, timeout):
    if host == "REPLACE_WITH_TARGET_PLC_IP":
        raise RuntimeError(
            "Please set --host or update DEFAULT_HOST in format_inference_runtime.py."
        )
    modiconInit.setdefaulttimeout(timeout)
    session_key, _, _ = modiconInit.modiconInit(host, port)
    return session_key.encode("latin1")


def reopen_target(host, port, timeout):
    try:
        modiconInit.tcpsock.close()
    except OSError:
        pass
    modiconInit.socket_reopen()
    return connect_target(host, port, timeout)


def send_seed(session_key, seed):
    global PACKET_COUNT
    frame = modiconInit.makeframe(session_key + seed)
    raw_response = modiconInit.sendframe(frame)
    PACKET_COUNT += 1
    return normalize_response(raw_response)


def safe_send_seed(session_key, seed, host, port, timeout):
    try:
        response = send_seed(session_key, seed)
        return response, session_key
    except (ConnectionAbortedError, ConnectionResetError, socket.timeout, OSError):
        session_key = reopen_target(host, port, timeout)
        response = send_seed(session_key, seed)
        return response, session_key


def response_weights(length):
    return [ALPHA ** depth for depth in range(length)]


def weighted_difference_score(response_a, response_b):
    max_len = max(len(response_a), len(response_b))
    weights = response_weights(max_len)
    score = 0.0
    for index in range(max_len):
        byte_a = response_a[index] if index < len(response_a) else None
        byte_b = response_b[index] if index < len(response_b) else None
        if byte_a != byte_b:
            score += weights[index]
    return score


def difference_threshold(responses):
    if not responses:
        return 0.0
    max_len = max(len(response) for response in responses)
    weights = response_weights(max_len)
    return sum(weights) / 2.0


def is_semantically_same(response, baseline_responses, threshold):
    if not baseline_responses:
        return False
    best_score = min(
        weighted_difference_score(response, baseline_response)
        for baseline_response in baseline_responses
    )
    return best_score <= threshold


def collect_single_byte_responses(seed, byte_index, session_key, host, port, timeout):
    tree = ProtoTree()
    root = tree.add_root("ROOT")
    responses = []
    for value in range(256):
        fuzzed = mutate_seed(seed, [byte_index], [value])
        response, session_key = safe_send_seed(session_key, fuzzed, host, port, timeout)
        responses.append(response)
        if response:
            tree.add_packet(response, fuzzed)
    return responses, tree, root, session_key


def verify_two_byte_mutation(seed, first_index, second_index, baseline_responses, session_key, host, port, timeout):
    threshold = difference_threshold(baseline_responses)
    for first_value in range(256):
        for second_value in range(256):
            fuzzed = mutate_seed(
                seed,
                [first_index, second_index],
                [first_value, second_value],
            )
            response, session_key = safe_send_seed(session_key, fuzzed, host, port, timeout)
            if not is_semantically_same(response, baseline_responses, threshold):
                return False, session_key
    return True, session_key


def infer_one_pair(seed, byte_a, session_key, host, port, timeout):
    byte_b = byte_a + 1

    responses_a, _, _, session_key = collect_single_byte_responses(
        seed, byte_a, session_key, host, port, timeout
    )
    same_ab, session_key = verify_two_byte_mutation(
        seed, byte_a, byte_b, responses_a, session_key, host, port, timeout
    )

    responses_b, _, _, session_key = collect_single_byte_responses(
        seed, byte_b, session_key, host, port, timeout
    )
    same_ba, session_key = verify_two_byte_mutation(
        seed, byte_b, byte_a, responses_b, session_key, host, port, timeout
    )

    return same_ab and same_ba, session_key


def build_byte_groups(seed_length, adjacent_same_flags):
    groups = []
    current_group = [0]

    for byte_index, same_semantics in enumerate(adjacent_same_flags, start=1):
        if same_semantics:
            current_group.append(byte_index)
        else:
            groups.append(current_group)
            current_group = [byte_index]

    groups.append(current_group)
    return groups


def infer_protocol_byte_groups(seed, session_key, host, port, timeout):
    adjacent_same_flags = []

    for byte_a in range(len(seed) - 1):
        same_semantics, session_key = infer_one_pair(seed, byte_a, session_key, host, port, timeout)
        adjacent_same_flags.append(same_semantics)

    return build_byte_groups(len(seed), adjacent_same_flags), session_key


def infer_protocol_groups_with_new_connection(seed, host, port, timeout):
    session_key = connect_target(host, port, timeout)
    try:
        groups, _ = infer_protocol_byte_groups(seed, session_key, host, port, timeout)
        return groups
    finally:
        try:
            modiconInit.tcpsock.close()
        except OSError:
            pass


def infer_protocol_runtime(protocol_name, seed, session_key, host, port, timeout):
    global PACKET_COUNT
    start_time = time.perf_counter()
    start_packets = PACKET_COUNT
    pair_count = 0

    for byte_a in range(len(seed) - 1):
        _, session_key = infer_one_pair(seed, byte_a, session_key, host, port, timeout)
        pair_count += 1

    elapsed_seconds = time.perf_counter() - start_time
    packet_count = PACKET_COUNT - start_packets
    print(f"{protocol_name}: {elapsed_seconds:.3f}s, packets={packet_count}")
    return {
        "protocol_name": protocol_name,
        "seed_hex": seed.hex(),
        "pair_count": pair_count,
        "total_elapsed_seconds": elapsed_seconds,
        "packet_count": packet_count,
    }, session_key


def write_results(rows, output_path):
    with Path(output_path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "protocol_name",
                "seed_hex",
                "pair_count",
                "total_elapsed_seconds",
                "packet_count",
                "byte_groups",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row["protocol_name"],
                    row["seed_hex"],
                    row["pair_count"],
                    f'{row["total_elapsed_seconds"]:.6f}',
                    row["packet_count"],
                    row["byte_groups"],
                ]
            )


def main():
    args = parse_args()
    rows = []
    overall_start_packets = PACKET_COUNT
    session_key = connect_target(args.host, args.port, args.timeout)

    try:
        overall_start = time.perf_counter()
        for protocol_name, seed in pick_protocols(args.protocol):
            groups, session_key = infer_protocol_byte_groups(
                seed,
                session_key,
                args.host,
                args.port,
                args.timeout,
            )
            row, session_key = infer_protocol_runtime(
                protocol_name,
                seed,
                session_key,
                args.host,
                args.port,
                args.timeout,
            )
            row["byte_groups"] = groups
            rows.append(row)
        overall_elapsed = time.perf_counter() - overall_start
    finally:
        try:
            modiconInit.tcpsock.close()
        except OSError:
            pass

    write_results(rows, args.output)
    print(f"overall elapsed: {overall_elapsed:.3f}s")
    print(f"overall packets: {PACKET_COUNT - overall_start_packets}")
    print(f"results written to: {args.output}")


if __name__ == "__main__":
    main()
