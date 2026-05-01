import random
from random import choice

## ------ parameter ------
## ------ arithmetic ------
_ARITH_MAX = 255 # max value of arithmetic
arith_list = list(range(-_ARITH_MAX, 0)) + list(range(1, _ARITH_MAX+1))
firstarith_list = list(range(-_ARITH_MAX,0)) + list(range(1, _ARITH_MAX+1))
SINGLE_ARITH_MAX = 40
singlearith_list = list(range(-SINGLE_ARITH_MAX,0)) + list(range(1,SINGLE_ARITH_MAX+1))
## ------ interest ------
_INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
_INTERESTING_16 = [-32768, -129, 0, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
_INTERESTING_32 = [-2147483648, -100663046, -32769, 0, 32768, 65535, 65536, 100663045, 2147483647]
## ------ dictionary ------
_USER_TOKEN = [

]
locate = 0
#cluster = [[0],[1,2],[3,4],[5],[6],[7,8]]


## ------ mutation function -------
## ------ bitflip ------	
def _bitflip(default_value,cluster):
    if not isinstance(default_value, bytes):
        raise TypeError
    mutation = "bitflip"
    test_num1 = 0
    for edge in cluster:
        print(edge)
        length = len(edge)
        # flip 1/1 1bit, step: 1bit
        flipvalue = 0x80
        #for i in range(length):
        for i in edge:
            print(i)
            for offset in range(8):
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:   
                    fuzz_value[i] = fuzz_value[i] ^ (flipvalue >> offset)
                    test_num1 += 1
                yield bytes(fuzz_value),i
        # flip 2/1 2bits, step: 1bit
        flipvalue = 0xC000
        #for i in range(length-1):
        a = edge[:]
        a.pop()
        #print(a)
        for i in a:
            for offset in range(8):
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:
                    fuzz_value[i] = fuzz_value[i] ^ (flipvalue >> (offset+8)) # the high byte
                    fuzz_value[i+1] = fuzz_value[i+1] ^ ((flipvalue >> offset) & 0x00FF) # the low byte
                    test_num1 += 1
                yield bytes(fuzz_value),i
        if length > 1:
            for offset in range(8):
                fuzz_value = list(default_value)
                fuzz_value[i+1] = fuzz_value[i+1] ^ (0xC0 >> offset) # the final byte
                test_num1 += 1
                yield bytes(fuzz_value),i
        # flip 4/1 4bits, step: 1bit
        flipvalue = 0xF000
        #for i in range(length-1):
        for i in a:
            for offset in range(8):
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:
                    fuzz_value[i] = fuzz_value[i] ^ (flipvalue >> (offset+8)) # the high byte
                    fuzz_value[i+1] = fuzz_value[i+1] ^ ((flipvalue >> offset) & 0x00FF) # the low byte
                    test_num1 += 1
                yield bytes(fuzz_value),i
        if length > 1:
            for offset in range(8):
                fuzz_value = list(default_value)
                fuzz_value[i+1] = fuzz_value[i+1] ^ (0xF0 >> offset) # the final byte
                test_num1 += 1
                yield bytes(fuzz_value),i
        # flip 8/8 1byte, step: 1byte
        #for i in range(length):
        for i in edge:
            #print(i)
            fuzz_value = list(default_value)
            if i == 10000:
                fuzz_value[i] = fuzz_value[i]
                test_num1 += 1
            else:
                fuzz_value[i] = fuzz_value[i] ^ 0xFF
                test_num1 += 1
            yield bytes(fuzz_value),i
        # flip 16/8 2bytes, step: 1byte
        if length >= 2:
            #for i in range(length-1):
            for i in a:
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:    
                    fuzz_value[i] = fuzz_value[i] ^ 0xFF
                    fuzz_value[i+1] = fuzz_value[i+1] ^ 0xFF
                    test_num1 += 1
                yield bytes(fuzz_value),i
        # flip 24/8 3bytes, step: 1byte
        if length >= 3:
            b = a[:]
            b.pop()
            #for i in range(length-3):
            for i in b:
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:
                    fuzz_value[i] = fuzz_value[i] ^ 0xFF
                    fuzz_value[i+1] = fuzz_value[i+1] ^ 0xFF
                    fuzz_value[i+2] = fuzz_value[i+2] ^ 0xFF
                    test_num1 += 1
                yield bytes(fuzz_value),i
            # last 3 bytes
            fuzz_value = list(default_value)
            fuzz_value[i+1] = fuzz_value[i+1] ^ 0xFF
            fuzz_value[i+2] = fuzz_value[i+2] ^ 0xFF
            test_num1 += 1
            yield bytes(fuzz_value),i
        # flip 32/8 4bytes, step: 1byte
        if length >= 4:
            c = b[:]
            c.pop()
            #for i in range(length-3):
            for i in c:
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num1 += 1
                else:
                    fuzz_value[i] = fuzz_value[i] ^ 0xFF
                    fuzz_value[i+1] = fuzz_value[i+1] ^ 0xFF
                    fuzz_value[i+2] = fuzz_value[i+2] ^ 0xFF
                    fuzz_value[i+3] = fuzz_value[i+3] ^ 0xFF
                    test_num1 += 1
                yield bytes(fuzz_value),i
            # last 3 bytes
            fuzz_value = list(default_value)
            fuzz_value[i+1] = fuzz_value[i+1] ^ 0xFF
            fuzz_value[i+2] = fuzz_value[i+2] ^ 0xFF
            fuzz_value[i+3] = fuzz_value[i+3] ^ 0xFF
            test_num1 += 1
            yield bytes(fuzz_value),i
## ------ arithmetic ------    
def _arithmetic(default_value,cluster):
    if not isinstance(default_value, bytes):
        raise TypeError
    #length = len(default_value)
    mutation = "arithmetic"
    test_num2 = 0
    for edge in cluster:
        length = len(edge)
        #arith_list = list(range(-_ARITH_MAX, 0)) + list(range(1, _ARITH_MAX+1)) # changed to global var
        # arith 8/8 step 8bit & 1 byte
        #for i in range(length):
        for i in edge:
            for arith_value in arith_list:
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num2 += 1
                else: 
                    fuzz_value[i] = (fuzz_value[i] + arith_value) & 0xFF # prevent from overflow
                    test_num2 += 1
                yield bytes(fuzz_value),i

        # arith 16/8 step 8bit & 1 word
        if length >= 2:
            #for i in range(length-1):
            a = edge[:]
            a.pop()
            for i in a:
                for arith_value in arith_list:
                    fuzz_value = list(default_value)
                    sum = (fuzz_value[i] << 8) ^ fuzz_value[i+1]
                    sum += arith_value
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num2 += 1
                    else:
                        fuzz_value[i] = (sum >> 8) & 0xFF
                        fuzz_value[i+1] = sum & 0xFF
                        test_num2 += 1
                    yield bytes(fuzz_value),i

        # arith 24/8 
        if length >= 3:
            #for i in range(length-3):
            b = a[:]
            b.pop()
            for i in b:
                for arith_value in arith_list:
                    fuzz_value = list(default_value)
                    sum = (fuzz_value[i] << 16) ^ (fuzz_value[i+1] << 8) ^ fuzz_value[i+2]
                    sum += arith_value
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num2 += 1
                    else:
                        fuzz_value[i] = (sum >> 16) & 0xFF
                        fuzz_value[i+1] = (sum >> 8) & 0xFF
                        fuzz_value[i+2] = sum & 0xFF
                        test_num2 += 1
                    yield bytes(fuzz_value),i       
        # arith 32/8 step 8bit & 1 dword
        if length >= 4:
            #for i in range(length-3):
            c = b[:]
            c.pop()
            for i in c:
                for arith_value in arith_list:
                    fuzz_value = list(default_value)
                    sum = (fuzz_value[i] << 24) ^ (fuzz_value[i+1] << 16) ^ (fuzz_value[i+2] << 8) ^ fuzz_value[i+3]
                    sum += arith_value
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num2 += 1
                    else:
                        fuzz_value[i] = (sum >> 24) & 0xFF
                        fuzz_value[i+1] = (sum >> 16) & 0xFF
                        fuzz_value[i+2] = (sum >> 8) & 0xFF
                        fuzz_value[i+3] = sum & 0xFF
                        test_num2 += 1
                    yield bytes(fuzz_value),i

## ------ interest ------
def _interest(default_value,cluster):
    if not isinstance(default_value, bytes):
        raise TypeError
    #length = len(default_value)
    mutation = "interest"
    test_num3 = 0
    for edge in cluster:
        length = len(edge)
        # interest 8/8
        #for i in range(length):
        for i in edge:
            for interest_value in _INTERESTING_8:
                fuzz_value = list(default_value)
                if i == 10000:
                    fuzz_value[i] = fuzz_value[i]
                    test_num3 += 1
                else:
                    fuzz_value[i] = interest_value & 0xFF
                    test_num3 += 1
                yield bytes(fuzz_value),i
        
        # interest 16/8
        if length >= 2:
            a = edge[:]
            a.pop()
            #for i in range(length-1):
            for i in a:
                for interest_value in _INTERESTING_16:
                    fuzz_value = list(default_value)
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num3 += 1
                    else:
                        fuzz_value[i] = (interest_value >> 8) & 0xFF
                        fuzz_value[i+1] = interest_value & 0xFF
                        test_num3 += 1
                    yield bytes(fuzz_value),i
        
        # interest 24/8
        if length >= 3:
            b = a[:]
            b.pop()
            #for i in range(length-1):
            for i in b:
                for interest_value in _INTERESTING_16:
                    fuzz_value = list(default_value)
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num3 += 1
                    else:
                        fuzz_value[i] = (interest_value >> 16) & 0xFF
                        fuzz_value[i+1] = (interest_value >> 8)& 0xFF
                        fuzz_value[i+2] = interest_value & 0xFF
                        test_num3 += 1
                    yield bytes(fuzz_value),i
        # interest 32/8
        if length >= 4:
            c = b[:]
            c.pop()
            #for i in range(length-3):
            for i in c:
                for interest_value in _INTERESTING_32:
                    fuzz_value = list(default_value)
                    if i == 10000:
                        fuzz_value[i] = fuzz_value[i]
                        test_num3 += 1
                    else:
                        fuzz_value[i] = (interest_value >> 24) & 0xFF
                        fuzz_value[i+1] = (interest_value >> 16) & 0xFF
                        fuzz_value[i+2] = (interest_value >> 8) & 0xFF
                        fuzz_value[i+3] = interest_value & 0xFF
                        test_num3 += 1
                    yield bytes(fuzz_value),i

## ------ determined mutation -------
def determined_mutate(default_value,cluster):
    for fuzz_value in _bitflip(default_value,cluster):
        yield fuzz_value
    for fuzz_value in _arithmetic(default_value,cluster):
        yield fuzz_value
    for fuzz_value in _interest(default_value,cluster):
        yield fuzz_value


def random_weight(b):
    total = 0
    for i in range(0,len(b)):
        total = total + b[i] 
    if total <= 30:
        ret = choice(range(len(b)))
    else:   
        ra = random.uniform(0, total)
        curr_sum = 0
        ret = None
        #keys = j        
        for i in range(0,len(b)):
            curr_sum += b[i]
            if ra <= curr_sum:
                ret = i
                break
    return ret
def random_unique(leaf):
    total = 0
    ret = None

    for i in range(0,len(leaf)):
        total = total + leaf[i]
    score = []
    for i in range(0,len(leaf)):
        score[i] = 100 - leaf[i]/total * 100
    ra = random.uniform(0,100)
    curr_sum = 0
    for i in range(0,len(score)):
        curr_sum += score[i]
        if ra <= curr_sum:
            ret = i
            break
    return ret

## ------ havoc -------
def havoc(seed) -> (bytes,int):
    if not isinstance(seed, bytes):
        raise TypeError
    length = len(seed)
    fuzz_seed = list(seed)
    tag = None
    p = choice(range(4)) # choose a random choice

    if p == 0: # flip 1 bit    
        flipvalue = 0x80
        r_index = choice(range(length))
        r_bit = choice(range(8))
        fuzz_seed[r_index] = fuzz_seed[r_index] ^ (flipvalue >> r_bit)
        tag = 0

    elif p == 1: # arith
        r_num = choice(arith_list)
        r_endian = choice(range(2))
        if length >= 2:
            r_pick = choice(range(2)) # arith byte or word
        elif length >= 4:
            r_pick = choice(range(3)) # arith byte, word or dword
        else:
            r_pick = 0 # can only arith byte

        if r_pick == 0: # arith byte
            r_index = choice(range(length))
            fuzz_seed[r_index] = (fuzz_seed[r_index] + r_num) & 0xFF
            tag = 1
        elif r_pick == 1: # arith word
            r_index = choice(range(length-1))
            if r_endian == 0: # big endian
                sum = (fuzz_seed[r_index] << 8) ^ fuzz_seed[r_index+1]
                sum += r_num
                fuzz_seed[r_index] = (sum >> 8) & 0xFF
                fuzz_seed[r_index+1] = sum & 0xFF
            else: # little endian
                sum = (fuzz_seed[r_index+1] << 8) ^ fuzz_seed[r_index]
                sum += r_num
                fuzz_seed[r_index+1] = (sum >> 8) & 0xFF
                fuzz_seed[r_index] = sum & 0xFF
            tag = 2
        elif r_pick == 2: # arith dword
            r_index = choice(range(length-3))
            if r_endian == 0:
                sum = (fuzz_seed[r_index] << 24) ^ (fuzz_seed[r_index+1] << 16) ^ (fuzz_seed[r_index+2] << 8) ^ fuzz_seed[r_index+3]
                sum += r_num
                fuzz_seed[r_index] = (sum >> 24) & 0xFF
                fuzz_seed[r_index+1] = (sum >> 16) & 0xFF
                fuzz_seed[r_index+2] = (sum >> 8) & 0xFF
                fuzz_seed[r_index+3] = sum & 0xFF
            else:
                sum = (fuzz_seed[r_index+3] << 24) ^ (fuzz_seed[r_index+2] << 16) ^ (fuzz_seed[r_index+1] << 8) ^ fuzz_seed[r_index]
                sum += r_num
                fuzz_seed[r_index+3] = (sum >> 24) & 0xFF
                fuzz_seed[r_index+2] = (sum >> 16) & 0xFF
                fuzz_seed[r_index+1] = (sum >> 8) & 0xFF
                fuzz_seed[r_index] = sum & 0xFF
            tag = 3
        else:
            raise ValueError(f'r_pick = {r_pick} : Value Error')

    elif p == 2: # interesting value
        r_endian = choice(range(2))
        if length >= 2:
            r_pick = choice(range(2)) # byte or word
        elif length >= 4:
            r_pick = choice(range(3)) # byte, word or dword
        else:
            r_pick = 0 # only byte
        
        if r_pick == 0: # byte
            r_value = choice(_INTERESTING_8)
            r_index = choice(range(length))
            fuzz_seed[r_index] = r_value & 0xFF
            tag = 4
        elif r_pick == 1: # word
            r_value = choice(_INTERESTING_16)
            r_index = choice(range(length-1))
            if r_endian == 0:
                fuzz_seed[r_index] = (r_value >> 8) & 0xFF
                fuzz_seed[r_index+1] = r_value & 0xFF
            else:
                fuzz_seed[r_index+1] = (r_value >> 8) & 0xFF
                fuzz_seed[r_index] = r_value & 0xFF
            tag = 5           
        elif r_pick == 2: # dword
            r_value = choice(_INTERESTING_32)
            r_index = choice(range(length-3))
            if r_endian == 0:
                fuzz_seed[r_index] = (r_value >> 24) & 0xFF
                fuzz_seed[r_index+1] = (r_value >> 16) & 0xFF
                fuzz_seed[r_index+2] = (r_value >> 8) & 0xFF
                fuzz_seed[r_index+3] = r_value & 0xFF
            else:
                fuzz_seed[r_index+3] = (r_value >> 24) & 0xFF
                fuzz_seed[r_index+2] = (r_value >> 16) & 0xFF
                fuzz_seed[r_index+1] = (r_value >> 8) & 0xFF
                fuzz_seed[r_index] = r_value & 0xFF
            tag = 6
        else:
            raise ValueError(f'r_pick = {r_pick} : Value Error')

    elif p == 3: # random byte
        r_index = choice(range(length))
        r_value = choice(range(256))
        fuzz_seed[r_index] = r_value & 0xFF
        tag = 7

    else:
        raise ValueError('undefined pick value')
    
    return bytes(fuzz_seed),tag
def move(list_a, b):
    for i in b:
        list_a.remove(i)
    return list_a

def per(lst, n, temp=[]):
    """从lst中取n个进行组合"""

    if not temp:
        lst_temp = move(lst[:], temp)
    else:
        x = lst.index(temp[-1])
        lst_temp = lst[(x + 1):]

    for i in range(len(lst_temp)):
        temp1 = temp + [lst_temp[i]]
        if len(temp1) < n:
            # print(f'--{temp1}')
            per(lst, n, temp1)
        else:
            return temp1
