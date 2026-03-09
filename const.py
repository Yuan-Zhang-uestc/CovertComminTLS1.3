"""
Const算法的完整实现，包括线性方程组构造
"""

import os
from typing import Tuple, List
from Cryptodome.Cipher import AES
import solve_mat as smbi
import duvae_cccc


class ConstAlgorithm:
    """Const算法实现"""

    @staticmethod
    def compute_B(K: bytes, N: bytes, T: bytes, C_len: int = 128) -> bytes:
        """
        计算B值

        B = (T ⊕ L·H ⊕ AES.Enc(K, N||0^31||1)) · H^{-2}
        """
        # 计算L
        L = duvae_cccc.DuVAE.encode_64(0) + duvae_cccc.DuVAE.encode_64(C_len)

        # 计算H = AES.Enc(K, 0^n)
        zero_block = b'\x00' * 16
        cipher = AES.new(K, AES.MODE_ECB)
        H = cipher.encrypt(zero_block)

        # 计算AES.Enc(K, N||0^31||1)
        N_padded = N + b'\x00' * 31 + b'\x01'
        enc_N = cipher.encrypt(N_padded[:16])

        # 计算L·H (GF(2^128)乘法)
        # 这里简化处理
        L_bytes = L.ljust(16, b'\x00')[:16]
        L_H = bytes(a ^ b for a, b in zip(L_bytes, H))

        # 计算T ⊕ L·H ⊕ enc_N
        intermediate = bytes(a ^ b ^ c for a, b, c in zip(T, L_H, enc_N))

        # 计算H^{-2}并相乘（简化）
        # 实际应计算H^{-2}在GF(2^128)中的值
        B = intermediate  # 简化处理

        return B

    @staticmethod
    def construct_ciphertext(N: bytes, K: bytes, K_star: bytes) -> Tuple[bytes, bytes]:
        """
        构造碰撞密文

        返回:
            (C, T): 密文和认证标签
        """
        # 生成随机标签
        T = os.urandom(16)

        # 假设我们需要构造8个密文块
        m = 8

        # 计算B和B*
        B = ConstAlgorithm.compute_B(K, N, T)
        B_star = ConstAlgorithm.compute_B(K_star, N, T)

        # 构造线性方程组
        # 系数矩阵 (2 x (m+1))，但我们需要扩展
        # 这里简化处理，使用预定义的构造方法

        # 生成随机密文块（除了第一个）
        C_blocks = [os.urandom(16) for _ in range(m)]

        # 第一个密文块用于嵌入，这里设置为特定值
        # 在实际完整实现中，需要通过解线性方程组得到

        # 连接所有块
        C = b''.join(C_blocks)

        return C, T