"""
TLS 1.3客户端实现
"""
import socket
import struct
import hashlib
from duvae_cccc import DuVAE
from eddsa_modified import ModifiedEdDSA
from Cryptodome.Random import get_random_bytes

class TLS13Client:
    """TLS 1.3客户端"""

    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.socket = None
        self.duvae = DuVAE()
        self.eddsa = ModifiedEdDSA()

        # 假设已经提前协商好域下密钥
        self.K_star = b'\x11' * 16  # 示例域下密钥

        # 握手阶段协商的密钥（域上密钥）
        self.K = None

        # 随机数
        self.client_random = None
        self.server_random = None

        print(f"[客户端] EdDSA 公钥: {self.eddsa.public_key[:8].hex()}...")

    def connect(self):
        """连接到服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"[客户端] 已连接到 {self.host}:{self.port}")

    def tls_handshake(self):
        """执行TLS握手"""
        print("[客户端] 开始TLS握手...")

        # 生成客户端随机数
        self.client_random = get_random_bytes(32)

        # 发送ClientHello
        client_hello = self.build_client_hello()
        self.send_record(0x16, client_hello)  # 0x16 = Handshake

        # 接收ServerHello
        record_type, handshake_msg = self.receive_record()
        if record_type != 0x16:
            raise Exception("期望握手记录")

        self.process_server_hello(handshake_msg)

        # 接收其他握手消息（Certificate, CertificateVerify, Finished等）
        # 这里简化处理

        print("[客户端] TLS握手完成")

    def build_client_hello(self):
        """构建ClientHello消息"""
        # TLS 1.3版本: 0x0304
        legacy_version = b'\x03\x04'

        # 随机数
        random = self.client_random

        # 会话ID（TLS 1.3中已废弃，但为了兼容性保留）
        session_id = b''

        # 密码套件
        # TLS_AES_128_GCM_SHA256 = 0x1301
        cipher_suites = b'\x13\x01'  # 仅一个套件

        # 压缩方法
        compression_methods = b'\x00'  # null压缩

        # 扩展
        extensions = self.build_extensions()

        # 构建ClientHello
        client_hello = (
            legacy_version +
            random +
            bytes([len(session_id)]) + session_id +
            len(cipher_suites).to_bytes(2, 'big') + cipher_suites +
            bytes([len(compression_methods)]) + compression_methods +
            len(extensions).to_bytes(2, 'big') + extensions
        )

        handshake_type = b'\x01'  # ClientHello
        length = len(client_hello).to_bytes(3, 'big')

        return handshake_type + length + client_hello

    def build_extensions(self):
        """构建扩展字段"""
        extensions = b''

        # 支持的版本扩展
        supported_versions = b'\x00\x2b\x00\x03\x02\x03\x04'  # TLS 1.3

        # 签名算法扩展
        signature_algorithms = b'\x00\x0d\x00\x08\x00\x06\x04\x03\x08\x04\x01\x00'  # ed25519

        extensions = supported_versions + signature_algorithms
        return extensions

    def process_server_hello(self, server_hello):
        """处理ServerHello消息"""
        # 跳过握手头部
        pos = 4  # 跳过类型和长度

        # 读取服务器版本
        server_version = server_hello[pos:pos+2]
        pos += 2

        # 读取服务器随机数
        self.server_random = server_hello[pos:pos+32]
        pos += 32

        # 读取密码套件
        cipher_suite = server_hello[pos:pos+2]
        pos += 2

        print(f"[客户端] 协商的密码套件: {cipher_suite.hex()}")

        # 在实际TLS中，这里会进行密钥派生
        # 简化：生成一个示例域上密钥
        self.K = hashlib.sha256(self.client_random + self.server_random).digest()[:16]
        print(f"[客户端] 域上密钥K: {self.K.hex()}")

    # tls13_client.py 中的 send_covert_message 方法修改
    def send_covert_message(self, covert_message):
        """
        发送隐蔽消息
        """
        print(f"[客户端] 准备发送隐蔽消息: {covert_message}")

        # 步骤1: 生成随机数N
        N = get_random_bytes(12)

        # 步骤2: 使用Const算法生成碰撞密文
        C, T = self.duvae.const(N, self.K, self.K_star)
        print(f"[客户端] 生成碰撞密文 C({len(C)}字节), T({len(T)}字节)")

        # 验证碰撞密文
        collision_valid = self.duvae.verify_collision(N, self.K, self.K_star, C, T)
        if not collision_valid:
            print("[客户端] 警告：生成的碰撞密文可能无法在两个密钥下都验证通过")

        # 步骤3: 使用Embed算法生成IV
        IV = self.duvae.embed(C, T, covert_message.encode(), self.K_star)
        print(f"[客户端] 生成IV: {IV.hex()}")

        # 步骤4: 将IV嵌入到EdDSA签名中
        handshake_hash = hashlib.sha256(self.client_random + self.server_random).digest()
        signature, embedded_signature = self.eddsa.sign_with_iv(handshake_hash, IV)

        print(f"[客户端] 生成带IV的签名: {signature[:16].hex()}...")

        # 步骤5: 发送应用数据记录，数据结构：签名(64字节) + N(12字节) + C + T
        data_to_send = signature[:64] + N + C + T  # 确保签名为64字节
        self.send_application_data(data_to_send)

        return IV, C, T, N, signature, collision_valid

    def send_application_data(self, data):
        """发送应用数据记录"""
        # 构建TLSCiphertext记录
        # opaque_type = 0x17 (application data)
        opaque_type = b'\x17'

        # legacy_record_version = 0x0303
        legacy_version = b'\x03\x03'

        # 长度
        length = len(data).to_bytes(2, 'big')

        # 记录头
        record_header = opaque_type + legacy_version + length

        # 整个记录
        record = record_header + data

        # 在实际TLS中，这里需要加密，但我们已经有密文了
        self.socket.send(record)
        print(f"[客户端] 发送应用数据记录 ({len(record)}字节)")

    def send_record(self, content_type, data):
        """发送TLS记录"""
        # 构建记录
        version = b'\x03\x03'  # TLS 1.2记录层版本（为了兼容性）
        length = len(data).to_bytes(2, 'big')

        record = bytes([content_type]) + version + length + data
        self.socket.send(record)

    def receive_record(self):
        """接收TLS记录"""
        # 读取记录头 (5字节)
        header = self.socket.recv(5)
        if len(header) < 5:
            raise Exception("连接关闭")

        content_type = header[0]
        version = header[1:3]
        length = int.from_bytes(header[3:5], 'big')

        # 读取记录数据
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise Exception("连接关闭")
            data += chunk

        return content_type, data

    def close(self):
        """关闭连接"""
        if self.socket:
            self.socket.close()
            print("[客户端] 连接已关闭")