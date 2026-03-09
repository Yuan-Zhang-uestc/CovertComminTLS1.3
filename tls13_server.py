"""
TLS 1.3服务器端实现
"""
import socket
import struct
import hashlib
from threading import Thread
from duvae_cccc import DuVAE
from eddsa_modified import ModifiedEdDSA
from Cryptodome.Random import get_random_bytes

class TLS13Server:
    """TLS 1.3服务器"""

    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.server_socket = None
        self.duvae = DuVAE()
        self.eddsa = ModifiedEdDSA()  # 在这个类的初始化中已经生成了密钥

        # 假设已经提前协商好域下密钥（与客户端相同）
        self.K_star = b'\x11' * 16  # 示例域下密钥

        # 握手阶段协商的密钥（域上密钥）
        self.K = None

        # 随机数
        self.client_random = None
        self.server_random = None

        # 注意：ModifiedEdDSA的初始化已经生成了密钥，所以这里不需要再调用kgen
        # 我们可以直接从self.eddsa中获取公钥和私钥
        self.private_key = self.eddsa.private_key
        self.public_key = self.eddsa.public_key

    def start(self):
        """启动服务器"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(5)  # 设置超时，避免永久阻塞

        print(f"[服务器] 监听 {self.host}:{self.port}")

        try:
            while True:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[服务器] 接受来自 {addr} 的连接")

                    # 在新线程中处理客户端
                    client_thread = Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.start()

                except socket.timeout:
                    # 超时继续循环，这样我们可以优雅地停止
                    continue
                except Exception as e:
                    print(f"[服务器] 接受连接时出错: {e}")
                    break
        except KeyboardInterrupt:
            print("[服务器] 收到中断信号，正在关闭...")
        finally:
            self.stop()

    def handle_client(self, client_socket):
        """处理客户端连接"""
        try:
            # TLS握手
            self.tls_handshake(client_socket)

            # 接收应用数据
            self.receive_application_data(client_socket)

        except Exception as e:
            print(f"[服务器] 错误: {e}")
        finally:
            client_socket.close()

    def tls_handshake(self, client_socket):
        """执行TLS握手"""
        print("[服务器] 开始TLS握手...")

        # 接收ClientHello
        record_type, handshake_msg = self.receive_record(client_socket)
        if record_type != 0x16:
            raise Exception("期望握手记录")

        self.process_client_hello(handshake_msg)

        # 发送ServerHello
        server_hello = self.build_server_hello()
        self.send_record(client_socket, 0x16, server_hello)

        # 发送其他握手消息（简化）

        print("[服务器] TLS握手完成")

    def process_client_hello(self, client_hello):
        """处理ClientHello消息"""
        # 跳过握手头部
        pos = 4  # 跳过类型和长度

        # 读取客户端版本
        client_version = client_hello[pos:pos+2]
        pos += 2

        # 读取客户端随机数
        self.client_random = client_hello[pos:pos+32]
        pos += 32

        print(f"[服务器] 客户端随机数: {self.client_random[:8].hex()}...")

    def build_server_hello(self):
        """构建ServerHello消息"""
        # 生成服务器随机数
        self.server_random = get_random_bytes(32)

        # TLS 1.3版本: 0x0304
        legacy_version = b'\x03\x04'

        # 密码套件
        cipher_suite = b'\x13\x01'  # TLS_AES_128_GCM_SHA256

        # 构建ServerHello
        server_hello = (
            legacy_version +
            self.server_random +
            cipher_suite +
            b'\x00'  # 压缩方法 = null
        )

        # 在实际TLS中，这里会有扩展

        handshake_type = b'\x02'  # ServerHello
        length = len(server_hello).to_bytes(3, 'big')

        # 生成域上密钥（简化）
        self.K = hashlib.sha256(self.client_random + self.server_random).digest()[:16]
        print(f"[服务器] 域上密钥K: {self.K.hex()}")

        return handshake_type + length + server_hello

    # tls13_server.py 中的 receive_application_data 方法修改
    def receive_application_data(self, client_socket):
        """接收应用数据"""
        print("[服务器] 等待接收应用数据...")

        # 接收记录
        record_type, encrypted_record = self.receive_record(client_socket)

        if record_type != 0x17:  # 0x17 = application data
            print(f"[服务器] 收到非应用数据记录: {record_type}")
            return

        print(f"[服务器] 收到应用数据记录 ({len(encrypted_record)}字节)")

        # 按照新的数据结构解析：签名(64字节) + N(12字节) + C + T(16字节)
        if len(encrypted_record) >= 64 + 12 + 16:
            signature = encrypted_record[:64]  # 签名，前64字节
            N = encrypted_record[64:76]  # N，12字节
            # 剩余部分是C + T，最后16字节是T
            remaining = encrypted_record[76:]

            if len(remaining) >= 16:
                T = remaining[-16:]  # 最后16字节是标签
                C = remaining[:-16]  # 剩余的是密文

                print(f"[服务器] 提取N: {N.hex()}")
                print(f"[服务器] 提取密文 C({len(C)}字节), 标签 T({len(T)}字节)")

                # 从签名中提取IV
                IV = self.eddsa.extract_iv_from_signature(signature)
                print(f"[服务器] 从签名中提取IV: {IV.hex()}")

                # 使用域下密钥提取隐蔽消息
                covert_message = self.duvae.extract(self.K_star, IV, C, T)

                if covert_message:
                    try:
                        # 尝试UTF-8解码，去除填充的空字节
                        covert_text = covert_message.rstrip(b'\x00').decode('utf-8', errors='ignore')
                        print(f"[服务器] 提取到隐蔽消息 ({len(covert_message)}字节): {covert_text}")
                    except UnicodeDecodeError:
                        # 如果不是UTF-8文本，显示十六进制
                        print(f"[服务器] 提取到隐蔽消息 ({len(covert_message)}字节, 十六进制): {covert_message.hex()}")
                else:
                    print("[服务器] 未提取到隐蔽消息")

                # 使用域上密钥审计（解密假消息），使用正确的N
                print("\n[服务器] 使用域上密钥审计...")
                fake_message = self.duvae.audit(self.K, N, C, T)

                if fake_message:
                    print(f"[服务器] 审计结果（假消息）: {fake_message[:32].hex()}...")
            else:
                print(f"[服务器] 数据格式错误，剩余数据不足: {len(remaining)}字节")
        else:
            print(f"[服务器] 数据太短: {len(encrypted_record)}字节")

    def send_record(self, socket, content_type, data):
        """发送TLS记录"""
        version = b'\x03\x03'
        length = len(data).to_bytes(2, 'big')

        record = bytes([content_type]) + version + length + data
        socket.send(record)

    def receive_record(self, socket):
        """接收TLS记录"""
        # 读取记录头 (5字节)
        header = socket.recv(5)
        if len(header) < 5:
            raise Exception("连接关闭")

        content_type = header[0]
        version = header[1:3]
        length = int.from_bytes(header[3:5], 'big')

        # 读取记录数据
        data = b''
        while len(data) < length:
            chunk = socket.recv(length - len(data))
            if not chunk:
                raise Exception("连接关闭")
            data += chunk

        return content_type, data

    def stop(self):
        """停止服务器"""
        if self.server_socket:
            self.server_socket.close()
            print("[服务器] 已停止")