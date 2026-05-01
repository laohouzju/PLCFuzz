from typing import List
from .BaseTree import Tree
import random
import sys
import numpy as np
import time
sys.setrecursionlimit(100000)

def Levenshtein_Distance(str1, str2):
    matrix = [[ i + j for j in range(len(str2) + 1)] for i in range(len(str1) + 1)]

    for i in range(1, len(str1)+1):
        for j in range(1, len(str2)+1):
            if(str1[i-1] == str2[j-1]):
                d = 0
            else:
                d = 1
                
            matrix[i][j] = min(matrix[i-1][j]+1, matrix[i][j-1]+1, matrix[i-1][j-1]+d)

    return matrix[len(str1)][len(str2)]


def hamming(a: list, b: list):
    count = 0
    for i in range(max(len(a), len(b))):
        a_bit = a[i] if i < len(a) else 0
        b_bit = b[i] if i < len(b) else 0
        count = count if a_bit == b_bit else count + 1
    return count

def getNumofCommonSubstr(str1, str2):
    #print('use')  
    lstr1 = len(str1)
    lstr2 = len(str2)
    record = [[0 for i in range(lstr2+1)] for j in range(lstr1+1)]
    maxNum = 0
    p = 0
      
    for i in range(lstr1):
        for j in range(lstr2):
            if str1[i] == str2[j]:
                record[i+1][j+1] = record[i][j] + 1
                if record[i+1][j+1] > maxNum:
                    maxNum = record[i+1][j+1]
                    p = i + 1
    return str1[p-maxNum:p], maxNum
  
class ProtoTree(Tree):
    class Node():
        def __init__(self, element, parent=None, children=[], count=1):
            self.element_pair = {element:count}
            self._parent:ProtoTree.Node = parent
            self._children:list = children[:]
            self.is_merged = False
            self.cut = False
            self.first = False
            self.unique_seed = []

        
    def validate(self, p) -> Node:
        #print('check')
        if not isinstance(p, self.Node):
            raise TypeError(f'p must be proper Node type (type : {type(p)})')
        if p._parent is p:
            raise ValueError('p is no longer valid')
        return p
    
    def __init__(self):
        self.__root = None
        self.__size = 0
        self.test = 0
    
    def __len__(self):
        return self.__size
    
    def root(self) -> Node:
        return self.__root
    
    def parent(self, p) -> Node:
        node = self.validate(p)
        return node._parent
    
    def children(self, p) -> List[Node]:
        node = self.validate(p)
        if len(node._children) <= 0:
            return []
        else:
            return [child for child in node._children]
    
    def siblings(self, p, self_include=True) -> List[Node]:
        parent = self.parent(p)
        if parent is None:
            return None
        else:
            if self_include:
                return self.children(parent)[:]
            else:
                children = self.children(parent)[:]
                for i in range(len(children)):
                    if children[i] == p:
                        del(children[i])
                return children

    def num_children(self, p) -> int:
        node = self.validate(p)
        return len(node._children)
    
    def element(self, p:Node) -> dict:
        return p.element_pair
    
    def element_pretty(self, p:Node) -> dict:
        r = {}
        for k,v in p.element_pair.items():
            r[hex(k)] = v
        return r

    def list_children(self, p) -> dict:
        self.validate(p)
        lc = self.children(p)
        if len(lc) <= 0:
            return None
        else:
            result = {}
            for child in lc:
                for k,v in child.element_pair.items():
                    result[hex(k)] = v
            return result

    def check_children(self, p:Node, e:int) -> Node:
        self.validate(p)
        lc = self.children(p)
        if len(lc) <= 0:
            return None
        else:
            for child in lc:
                if e in child.element_pair.keys():
                    return child
            return None
    
    def add_root(self, e) -> Node:
        if self.__root is not None:
            raise ValueError('Root exists')
        else:
            self.__size += 1
            self.__root = self.Node(e)
            return self.__root
    
    def add_child(self, e, p) -> Node:
        node = self.validate(p)
        self.__size += 1
        node._children.append(self.Node(e,node))
        return node._children[-1]
    
    def replace(self, p, e):
        pass
    
    def add_count(self, p:Node, key=None) -> Node:
        node = self.validate(p)
        if node.is_merged:
            if key is None:
                raise ValueError('key cannot be None if node is merged')
            else:
                node.element_pair[key] += 1
        else:
            if key is None:
                key = tuple(node.element_pair)[0]
            node.element_pair[key] += 1
        return p

    
    def allpaths(self, pstart:Node) -> List[List]:
        if self.is_root(pstart):
            mode = 1
        else:
            mode = 0
        paths = []

        def getpath(p, path:List):
            path.append(tuple(p.element_pair)[0])
            if self.is_leaf(p):
                if mode == 1:
                    paths.append(path[1:])
                else:
                    paths.append(path)
                return           
            for child in self.children(p):
                getpath(child, path[:])
        
        if not self.is_leaf(pstart):
            getpath(pstart, [])
        return paths
    

    

    def add_packet(self, packet:bytes, seed:bytes) -> bool:
        start_time = time.time()
        pnode = self.root()
        newpath = False
        flag_path = True
        count = 0 
        paths = []
        depth = 0
        #length = len(packet)
        #score = np.arange(0,100,length)
        unique = 0
        for _byte in packet:
            new_pnode = self.check_children(pnode, _byte)
            if new_pnode is None:
                for child in self.children(pnode):
                    if child.is_merged:
                        new_pnode = child
                        new_pnode.element_pair[_byte] = 1
                        break
                else:
                    if flag_path:
                        paths = self.allpaths(pnode)
                        flag_path = False
                        index = count
                    new_pnode = self.add_child(_byte, pnode)
                    newpath = True
                    unique += 1
                    depth = self.depth(pnode)
                    new_pnode.first = False

            elif new_pnode.first == True:
                    newpath = True
                    unique += 1
                    new_pnode.first = False
  
            else:
                self.add_count(new_pnode,key=_byte)
                if new_pnode.cut:
                    break
            pnode = new_pnode
            count += 1

        # check
        
        if paths:
            for p in paths:
                p = p[0:60]
                packet = packet[0:60+index]
                substr = getNumofCommonSubstr(packet[index:],p)
                if not any(substr):
                    pass
                score1 = len(substr)/len(packet[index:])
                score2 = len(substr)/len(p)
                if min(score1,score2) > 0.8:
                    newpath = False
                    self.test += 1
                    break            
        if newpath:
            pnode.unique_seed.append(seed)
        #else:
        #    length.append(self.depth(pnode))

        end_time = time.time()
        check_time = end_time - start_time
        return newpath,unique,depth,check_time


    def tree_size(self):
        if self.__root is None:
            return 0

        def size(node):
            count = 1
            for child in self.children(node):
                count += size(child)
            return count

        return size(self.__root)


    def delete(self, p):
        # TODO
        pass
    
    def cut(self, p):
        p.cut = True
        m = 0
        for node in self.postorder(p):
            if node is not p:
                p.unique_seed += node.unique_seed
                m += 1
        p._children = []
        self.__size -= m


    def merge(self, main_p, *ps, **kwargs):
        if len(ps) <= 0:
            raise ValueError('ps has no Value')
        main_node = self.validate(main_p)
        #if self.is_root(main_p):
        #    raise ValueError('please do not merge ROOT node')
        for p in ps:
            p_node = self.validate(p)
            for key,value in p_node.element_pair.items():
                if key in main_node.element_pair:
                    main_node.element_pair[key] += value
                else:
                    main_node.element_pair[key] = value
            main_node.unique_seed += p_node.unique_seed
            if p.cut:
                main_node.cut = True
            for child_node in p_node._children:
                child_node._parent = main_node
                main_node._children.append(child_node)
            p_node._parent._children.remove(p_node)
            del p_node
            self.__size -= 1
        if len(main_node.element_pair) > 1:
            main_node.is_merged = True
        if main_node.cut:
            self.cut(main_node)
        dup_dict = {}
        dup_dict_merged = {}
        merge_count = 0
        for child in main_node._children:
            #key = tuple(child.element_pair.keys())
            key = tuple(child.element_pair)
            if child.is_merged:
                merge_count += 1
                if key in dup_dict:
                    dup_dict_merged[key].append(child)
                    dup_dict_merged[key][0] += 1
                else:
                    dup_dict_merged[key] = [1,child]
            else:
                if key in dup_dict:
                    dup_dict[key].append(child)
                    dup_dict[key][0] += 1
                else:
                    dup_dict[key] = [1,child]
        if merge_count >= 1:
            tmp = {}
            for key1,value1 in dup_dict_merged.items():
                for key2,value2 in tmp.items():
                    key_new = tuple(set(key1+key2))
                    if len(key_new) != len(key1) + len(key2):
                        tmp[key_new] = [value1[0]+value2[0]] + value1[1:] + value2[1:]
                        del tmp[key2]
                        break
                else:
                    tmp[key1] = value1
            key2_list = tmp.keys()
            for key1,value1 in dup_dict.items():
                for key2 in key2_list: 
                    if key1[0] in key2:
                        tmp[key2][0] += value1[0]
                        tmp[key2] += value1[1:]
                        break
                else:
                    tmp[key1] = value1
        for plist in dup_dict.values():
            if plist[0] >= 2:
                r = [p for p in plist[1:]]
                self.merge(r[0],*r[1:])

    def preorder(self, p):
        yield p
        for child in self.children(p):
            for other in self.preorder(child):
                yield other
    
    def postorder(self, p):
        for child in self.children(p):
            for other in self.preorder(child):
                yield other
        yield p
    
    def breadthfirst(self, p):
        queue = []
        queue.append(p)
        while len(queue) != 0:
            p = queue[0]
            for child in self.children(p):
                queue.append(child)
            del(queue[0])
            yield p
    






