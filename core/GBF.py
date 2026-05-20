# gbf.py
import os
import struct
import hashlib
import random

def bytes_xor(a: bytes, b: bytes) -> bytes:
    """按位异或两个等长字节串"""
    return bytes(x ^ y for x, y in zip(a, b))

def fingerprint(item: str, psi: int) -> bytes:
    """
    根据输入字符串生成固定长度的指纹。
    psi: 指纹长度（比特），应为8的倍数，返回 psi/8 字节。
    """
    byte_len = psi // 8
    return hashlib.sha256(item.encode('utf-8')).digest()[:byte_len]

class GarbledBloomFilter:
    def __init__(self, size: int, hash_count: int, psi: int):
        """
        size: 布隆过滤器数组大小
        hash_count: 哈希函数个数（t）
        psi: 每个单元存储比特数（应为8的倍数）
        """
        self.size = size
        self.hash_count = hash_count
        self.psi = psi
        self.byte_len = psi // 8
        # 初始化数组：每个位置为固定长度的全0字节串
        self.array = [b'\x00' * self.byte_len for _ in range(size)]

    def _hashes(self, item: str) -> list:
        """生成 hash_count 个候选位置，采用双哈希技巧"""
        hash1 = int(hashlib.sha256(item.encode('utf-8')).hexdigest(), 16)
        hash2 = int(hashlib.md5(item.encode('utf-8')).hexdigest(), 16)
        return [(hash1 + i * hash2) % self.size for i in range(self.hash_count)]

    def add(self, item: str):
        """
        添加一个元素到混淆布隆过滤器中。
        具体步骤：
         1. 计算元素的 fingerprint（指纹）。
         2. 计算元素对应的 t 个哈希位置。
         3. 随机选择其中一个位置为特殊位置，其余位置随机生成份额。
         4. 特殊位置的份额为 fingerprint 与其它份额的异或。
         5. 最后，将这 t 个份额与对应位置已有的值进行异或更新。
        """
        fp_val = fingerprint(item, self.psi)
        positions = self._hashes(item)
        # 随机选择一个特殊位置
        special_idx = random.choice(positions)
        random_shares = {}
        xor_sum = b'\x00' * self.byte_len
        for pos in positions:
            if pos == special_idx:
                continue
            r = os.urandom(self.byte_len)
            random_shares[pos] = r
            xor_sum = bytes_xor(xor_sum, r)
        # 特殊位置的份额
        special_share = bytes_xor(fp_val, xor_sum)
        random_shares[special_idx] = special_share
        # 更新每个候选位置的值（采用异或累积更新）
        for pos in positions:
            self.array[pos] = bytes_xor(self.array[pos], random_shares[pos])

    def query(self, item: str) -> bool:
        """
        查询元素是否存在。计算 t 个哈希位置的值异或结果，
        如果等于 fingerprint(item) 则可能存在，否则不存在。
        """
        positions = self._hashes(item)
        xor_result = b'\x00' * self.byte_len
        for pos in positions:
            xor_result = bytes_xor(xor_result, self.array[pos])
        return xor_result == fingerprint(item, self.psi)
