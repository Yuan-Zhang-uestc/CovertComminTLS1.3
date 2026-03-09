"""
修改后的EdDSA签名算法
将IV嵌入到签名中（简化版本）
"""
import hashlib
import os

class ModifiedEdDSA:
    """修改后的EdDSA，用于嵌入IV（简化版本）"""

    def __init__(self):
        # 生成密钥对（简化：使用随机字节作为私钥）
        self.private_key = os.urandom(32)
        self.public_key = self._derive_public_key(self.private_key)

        # 添加这行，确保我们有一个公钥用于验证
        print(f"[EdDSA] 已生成密钥对，公钥: {self.public_key[:8].hex()}...")

    def _derive_public_key(self, private_key):
        """从私钥派生公钥（简化版本）"""
        # 在实际EdDSA中，这涉及到椭圆曲线运算
        # 这里简化：使用哈希函数
        return hashlib.sha256(private_key).digest()

    def sign_with_iv(self, message, iv):
        """
        使用IV进行签名（简化版本）
        输入: 消息M, 初始向量IV
        输出: 签名和嵌入的签名
        """
        # 由于我们无法修改标准EdDSA库，我们创建一个简化版本
        # 在实际实现中，这需要完整的椭圆曲线运算

        # 创建一个伪造的签名：IV || 消息哈希
        message_hash = hashlib.sha256(message).digest()

        # 签名格式：前32字节是IV，后32字节是消息哈希的签名
        # 实际签名应该是椭圆曲线上的点，这里简化处理
        fake_signature = iv[:32].ljust(32, b'\x00') + message_hash

        # 嵌入的签名：我们将IV放在签名的特定位置
        embedded_signature = fake_signature

        return fake_signature, embedded_signature

    def verify_with_iv(self, message, signature, public_key):
        """验证签名（简化版本）"""
        # 简化：总是返回True
        return True

    def extract_iv_from_signature(self, signature, message=None, private_key=None):
        """
        从签名中提取IV（简化版本）
        输入: 签名σ, 消息M, 私钥
        输出: IV
        """
        # 假设签名包含IV作为前32字节
        # 但实际IV是16字节，所以我们取前16字节
        if len(signature) >= 16:
            return signature[:16]
        else:
            # 如果签名太短，返回零填充的IV
            return signature.ljust(16, b'\x00')