"""
强制审查者实现
"""
from duvae_cccc import DuVAE


class Auditor:
    """强制审查者"""

    def __init__(self):
        self.duvae = DuVAE()

    def intercept_and_audit(self, ciphertext, tag, K, N):
        """
        拦截并审计通信
        输入: 密文C, 标签T, 域上密钥K, 随机数N
        输出: 审计结果（假消息）
        """
        print("[审查者] 拦截到通信，开始审计...")
        print(f"[审查者] 密文长度: {len(ciphertext)}字节")
        print(f"[审查者] 标签: {tag[:8].hex()}...")
        print(f"[审查者] 使用域上密钥K: {K.hex()}")

        # 使用DuVAE的audit方法解密
        result = self.duvae.audit(K, N, ciphertext, tag)

        if result is None:
            print("[审查者] 审计失败: GHASH验证失败")
            return None
        else:
            print(f"[审查者] 审计成功，解密结果: {result[:32].hex()}...")
            print(f"[审查者] 解释: 这看起来像是一串随机密钥数据")
            return result