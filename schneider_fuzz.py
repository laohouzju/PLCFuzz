from mutate import modiconInit, mutate2
from Tree.ProtoTree import ProtoTree
from random import choice
from datetime import datetime
import traceback
import sys
import os
import pickle
from time import sleep
from pathlib import Path
from format_inference_runtime import infer_protocol_groups_with_new_connection

# Public-release configuration.
# Replace TARGET_HOST with the IP address of the PLC under test.
TARGET_HOST = "REPLACE_WITH_TARGET_PLC_IP"
TARGET_PORT = 502


# These directories are used by the public release to store logs and serialized results.
CRASH_LOG_DIR = Path("logs")
RESULT_DIR = Path("results")

d_SEEDS = [
    b'\x20\x01\x13\x00\x00\x00\x00\x00\x64\x64',
    b'\x22\x04\xe9\x0d\x02\x01\x02\x2b\x00\x01\x00\x00\xb8',
    b'\x25\x01\x00\x03\x01\x00\x00\x00\x02\x00\x23\x23\x56\x32',
    b'\x29\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x28\x00\x00\x00\x00\x00\x00',
    b'\x34\x00\x01\x01\x00',
    b'\x41\xff\x00',
    b'\x10\x25\x10\x00\x00\x05\x4f\x57\x4e\x44\x45',
    b'\x50\x15\x00\x01\x0b'
]

CLUSTER = []
havoc_SEEDS = [

]
crash_SEEDS = [

]
UNEXPECTED_PAIRS = {}

testcase_num = 0
MAINTENANCE_COUNTER = 0
DERTERMINED_NUM = 0
HAVOC_NUM = 0
unique_path_num = 0
locate = 0
#unique_path_count = [0]*8
# --------------- functions ---------------

def ensure_output_dirs():
    CRASH_LOG_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)




def infer_seed_clusters():
    inferred_clusters = []
    for seed in d_SEEDS:
        protocol_groups = infer_protocol_groups_with_new_connection(
            seed,
            TARGET_HOST,
            TARGET_PORT,
            8.0,
        )
        inferred_clusters.append(protocol_groups)
    return inferred_clusters

def d_mutate(func, default_value, session_key,cluster):
    for payload,locate in mutate2.determined_mutate(default_value,cluster):
        if func+payload not in crash_SEEDS:#TODO test
            print(bytes(func)+payload)
            print(crash_SEEDS)
            resp = modiconInit.sendframe(modiconInit.makeframe(session_key+func+payload))
            global testcase_num
            testcase_num += 1
            fuzz_seed = func+payload
            yield fuzz_seed,resp,locate

def tree_maintenance(tree:ProtoTree, root:ProtoTree.Node):
    global MAINTENANCE_COUNTER
    global havoc_SEEDS
    MAINTENANCE_COUNTER += 1
    merge_threshold = 300
    old_len = len(tree)
    old_seed = len(havoc_SEEDS)
    # merge tree
    for p in tree.preorder(root):
        children = tree.children(p)
        child_num = 0
        for child in children:
            child_num += len(child.element_pair)
            if child.is_merged:
                child_num = len(child.element_pair)
                break
        score = child_num + 3*tree.depth(p)
        if score >= 120:
            tree.cut(p)
        elif len(children) >= 2 and child_num >= merge_threshold:
            tree.merge(children[0],*children[1:])

    havoc_SEEDS = []
    for p in tree.breadthfirst(root):
        if tree.is_leaf(p) and p.unique_seed:
            havoc_SEEDS.append(choice(p.unique_seed))
    #havoc_SEEDS += crash_SEEDS[:]
    os.system('cls')
    print(f'maintenance counter: {MAINTENANCE_COUNTER}')    
    for e,c in tree.list_children(root).items():
        print(e,c)
    print(f'tree size : {old_len} -> {len(tree)}')
    print(f'seed num : {old_seed} -> {len(havoc_SEEDS)}')
    print(f'determined seeds : {len(d_SEEDS)}')
    print(f'determined num : {DERTERMINED_NUM}')
    print(f'havoc num : {HAVOC_NUM}')
    
    
# --------------- main ---------------

if __name__ == '__main__':
    crash_count = 0 # TODO:test
    sys.setrecursionlimit(10000000)
    start_time = datetime.now()
    os.system('cls')
    # Set TARGET_HOST above to the PLC IP address used in your environment.
    ensure_output_dirs()
    if TARGET_HOST == "REPLACE_WITH_TARGET_PLC_IP":
        raise RuntimeError("Please set TARGET_HOST in fuzz.py before running the public release.")
    CLUSTER.extend(infer_seed_clusters())
    print("Inferred byte groups for Schneider UMAS seeds:")
    for seed_index, byte_groups in enumerate(CLUSTER):
        print(f"seed[{seed_index}] -> {byte_groups}")
    host = TARGET_HOST
    port = TARGET_PORT
    session_key, max_data_len, max_block_len =  modiconInit.modiconInit(host,port)
    session_key = session_key.encode('latin1')
    ptree = ProtoTree()
    hroot = ptree.add_root('ROOT')
    #func = b'\x20'
    # fuzz start
    try:
        while True:

            try:
                if (HAVOC_NUM >= 5000):
                    tree_maintenance(ptree, hroot)
                    print('state : havoc')
                    HAVOC_NUM = 0
                #tmp_seeds = []
                for seed in d_SEEDS:
                    func = seed[:1]
                    com_i = d_SEEDS.index(seed)
                    cluster = CLUSTER[com_i]
                    if (DERTERMINED_NUM >= 5000):
                        tree_maintenance(ptree, hroot)
                        print('state : determined mutation')
                        DERTERMINED_NUM = 0
                    for fuzz_seed,ori_resp,fuzz_locate in d_mutate(func, seed[1:], session_key, cluster):
                        #print(seed)
                        resp = ori_resp[9:]
                        if resp:
                            DERTERMINED_NUM += 1
                            if resp[0] != 0xfe and resp[0] != 0xfd:
                                print(f'unexpected response : {ori_resp}')
                                UNEXPECTED_PAIRS[fuzz_seed] = ori_resp
                            ptree.add_packet(resp,fuzz_seed)
                d_SEEDS = []

                # havoc
                if not havoc_SEEDS:
                    tree_maintenance(ptree, hroot)
                    print('state : start')
                    DERTERMINED_NUM,HAVOC_NUM = 0,0
                seed = choice(havoc_SEEDS)
                payload,tag = mutate2.havoc(seed[1:])
                func = seed[:1]
                fuzz_seed = func + payload
                if fuzz_seed not in crash_SEEDS:#TODO test
                    ori_resp = modiconInit.sendframe(modiconInit.makeframe(session_key+fuzz_seed))
                    testcase_num += 1
                resp = ori_resp[9:]
                if resp:
                    HAVOC_NUM += 1
                    newpath = ptree.add_packet(resp,fuzz_seed)
                    if newpath:
                        d_SEEDS.append(fuzz_seed)
                        unique_path_num += 1
                        #unique_path_count[tag] += 1
                    

            except ConnectionAbortedError:
                time_cost = (datetime.now() - start_time).seconds
                hours = time_cost // 3600
                minutes = (time_cost - hours * 3600) // 60
                seconds = time_cost - hours * 3600 - minutes * 60
                print(f'time cost : {hours}:{minutes}:{seconds}')
                with (CRASH_LOG_DIR / 'plctime.txt').open('a', encoding='utf-8') as f0:
                    print(f'time cost : {hours}:{minutes}:{seconds}',file = f0)
                print('\nconnection aborted')
                crash_count += 1
                with (CRASH_LOG_DIR / 'plccrashcount.txt').open('a', encoding='utf-8') as f1:
                    print(f'crash_count : {crash_count}',file = f1)
                crash_SEEDS.append(fuzz_seed)
                with (CRASH_LOG_DIR / 'plccrashseed.txt').open('a', encoding='utf-8') as f2:
                    print(f'crash_seed : {fuzz_seed}',file = f2)
                if MAINTENANCE_COUNTER == 0:
                    tree_maintenance(ptree, hroot)
                    d_SEEDS = []
                modiconInit.tcpsock.close()
                
                os.system("cls")
                modiconInit.socket_reopen()
                session_key, max_data_len, max_block_len =  modiconInit.modiconInit(host,port)
                session_key = session_key.encode('latin1')
                

            except WindowsError:
                time_cost = (datetime.now() - start_time).seconds
                hours = time_cost // 3600
                minutes = (time_cost - hours * 3600) // 60
                seconds = time_cost - hours * 3600 - minutes * 60
                print(f'time cost : {hours}:{minutes}:{seconds}')
                print('\nconnection aborted')
                crash_count += 1
                crash_SEEDS.append(fuzz_seed)
                if MAINTENANCE_COUNTER == 0:
                    tree_maintenance(ptree, hroot)
                    d_SEEDS = []
                modiconInit.tcpsock.close()
                
                os.system("cls")
                modiconInit.socket_reopen()
                session_key, max_data_len, max_block_len =  modiconInit.modiconInit(host,port)
                session_key = session_key.encode('latin1')

    except KeyboardInterrupt:
        print('\nkeyboard interrupt by user')
    except:
        exc_type, exc_value, exc_tb = sys.exc_info()
        print(f'\nUnexpected error : {exc_type}')
        print(exc_value)
        traceback.print_tb(exc_tb)
    finally:
        #print(f'\ncurrent fuzzseed : {fuzz_seed}\n')
        modiconInit.tcpsock.close()
        # save data
        
        print('saving data')
        with (RESULT_DIR / 'unexpected_pairs.pickle').open('wb') as f:
            pickle.dump(UNEXPECTED_PAIRS, f, pickle.HIGHEST_PROTOCOL)
        with (RESULT_DIR / 'fuzztree.pickle').open('wb') as f:
            pickle.dump(ptree, f, pickle.HIGHEST_PROTOCOL)
        
        # show result
        count = 0
        for node in ptree.preorder(hroot):
            if node.is_merged:
                count += 1
        print(f'merged node : {count}')
        print(fuzz_seed)
        time_cost = (datetime.now() - start_time).seconds
        hours = time_cost // 3600
        minutes = (time_cost - hours * 3600) // 60
        seconds = time_cost - hours * 3600 - minutes * 60
        print(f'time cost : {hours}:{minutes}:{seconds}')
        print(f'crash_count = {crash_count}')
        print(f'unique_path = {unique_path_num}')
        print(f'testcase_num = {testcase_num}')
