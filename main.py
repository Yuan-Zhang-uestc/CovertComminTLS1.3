"""
主测试程序
"""
import time
import threading
from tls13_client import TLS13Client
from tls13_server import TLS13Server
from auditor import Auditor
from Cryptodome.Cipher import AES

def run_server():
    """运行服务器"""
    server = TLS13Server()
    server.start()


# main.py 中的 run_client 函数修改
def run_client():
    """运行客户端"""
    # 等待服务器启动
    time.sleep(2)

    client = TLS13Client()
    client.connect()

    # 执行TLS握手
    client.tls_handshake()

    # 发送隐蔽消息
    covert_message = "HelloCovertMsg!"  # 16字节的英文消息

    print(f"\n[客户端] 开始发送隐蔽消息: {covert_message}")
    IV, C, T, N, signature, collision_valid = client.send_covert_message(covert_message)

    # 模拟审查者拦截
    print("\n" + "=" * 50)
    print("强制审查者视角")
    print("=" * 50)
    print(f"[主程序] 审查者使用N: {N.hex()}")
    auditor = Auditor()

    # 审查者使用域上密钥K解密，使用正确的N
    fake_message = auditor.intercept_and_audit(C, T, client.K, N)

    if fake_message:
        if isinstance(fake_message, bytes):
            print(f"\n审查者看到的消息(十六进制): {fake_message[:32].hex()}...")
            try:
                # 尝试解码为文本
                text = fake_message[:16].decode('utf-8', errors='ignore')
                print(f"审查者看到的消息(文本): {text}")
            except:
                pass
        else:
            print(f"审查者看到的消息: {fake_message}")
        print("\n审查者认为: 这是一次正常的TLS通信，传输的是密钥数据")
    else:
        print("审查者: 解密失败")

    print(f"\n碰撞密文验证结果: {'成功' if collision_valid else '失败'}")

    # 关闭连接
    client.close()

    print("\n" + "=" * 50)
    print("隐蔽通信成功")
    print("=" * 50)
    print(f"发送方发送的隐蔽消息: {covert_message}")
    print(f"IV: {IV.hex()}")
    print(f"N: {N.hex()}")
    print("\n在审查者看来，这只是一次正常的TLS 1.3通信")


def main():
    """主函数"""
    print("=== TLS 1.3 with DuVAE/CCCC 隐蔽通信演示 ===\n")

    # 启动服务器线程
    server_thread = threading.Thread(target=run_server, name="ServerThread")
    server_thread.daemon = True  # 设置为守护线程
    server_thread.start()

    print("[主程序] 服务器线程已启动")

    # 等待服务器完全启动
    time.sleep(2)

    # 运行客户端
    run_client()

    # 等待一段时间让所有操作完成
    time.sleep(3)
    print("\n演示完成!")

if __name__ == "__main__":
    main()