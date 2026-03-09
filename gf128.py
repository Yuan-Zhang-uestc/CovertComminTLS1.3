"""
GF(2^128)有限域运算模块
使用不可约多项式 x^128 + x^7 + x^2 + x + 1
参考：AES-GCM规范
"""
from Cryptodome.Util.number import bytes_to_long, long_to_bytes

class GF128:
    """GF(2^128)有限域，使用不可约多项式 x^128 + x^7 + x^2 + x + 1"""

    # 不可约多项式 x^128 + x^7 + x^2 + x + 1
    # 二进制: 1 00000000 ... 10000111 (128位多项式，第7、2、1、0位为1)
    # 十六进制: 0x87 << 120 = 0x87000000000000000000000000000000
    MOD = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

    @staticmethod
    def add(a, b):
        """加法：异或"""
        return a ^ b

    @staticmethod
    def sub(a, b):
        """减法：同加法"""
        return a ^ b

    @staticmethod
    def mul(a, b):
        """GF(2^128)乘法 - 使用俄罗斯农民算法，从高位到低位"""
        # 参考：https://en.wikipedia.org/wiki/Finite_field_arithmetic
        res = 0
        for i in range(127, -1, -1):
            # 将结果左移1位
            res <<= 1
            # 如果结果超过128位，进行模约简
            if res & (1 << 128):
                res ^= GF128.MOD

            # 如果a的第i位为1，则异或b
            if (a >> i) & 1:
                res ^= b

        # 确保结果在128位内
        return res & ((1 << 128) - 1)

    @staticmethod
    def mul_alt(a, b):
        """另一种乘法实现 - 从低位到高位，用于验证"""
        res = 0
        v = b

        for i in range(128):
            if (a >> i) & 1:
                res ^= v

            # 检查v的最高位
            if v & (1 << 127):
                v = (v << 1) ^ ((1 << 128) | (0x87 << 120))
            else:
                v <<= 1

            # 确保v在128位内
            v &= (1 << 128) - 1

        return res

    @staticmethod
    def power(x, n):
        """幂运算：平方-乘算法"""
        result = 1
        while n > 0:
            if n & 1:
                result = GF128.mul(result, x)
            x = GF128.mul(x, x)
            n >>= 1
        return result

    @staticmethod
    def inverse(x):
        """计算逆元：x^(2^128-2)"""
        # 使用平方-乘算法
        return GF128.power(x, (1 << 128) - 2)

    @staticmethod
    def div(a, b):
        """除法：a * b^{-1}"""
        b_inv = GF128.inverse(b)
        return GF128.mul(a, b_inv)

    @staticmethod
    def bytes_to_int(b):
        """字节串转整数（大端序）"""
        if len(b) > 16:
            b = b[:16]
        return bytes_to_long(b.ljust(16, b'\x00'))

    @staticmethod
    def int_to_bytes(x):
        """整数转字节串（16字节，大端序）"""
        return long_to_bytes(x, 16)

    @staticmethod
    def test_multiplication():
        """测试乘法实现"""
        print("\n[GF128测试] 测试乘法实现...")

        # 测试1: 1 * 1 = 1
        result = GF128.mul(1, 1)
        expected = 1
        print(f"1 * 1 = {hex(result)} (期望: {hex(expected)}) - {'通过' if result == expected else '失败'}")

        # 测试2: 2 * 3 = 6
        result = GF128.mul(0x2, 0x3)
        expected = 0x6
        print(f"2 * 3 = {hex(result)} (期望: {hex(expected)}) - {'通过' if result == expected else '失败'}")

        # 测试3: x * x = x^2
        x = 0x2  # 多项式x
        result = GF128.mul(x, x)
        expected = 0x4  # x^2
        print(f"x * x = {hex(result)} (期望: {hex(expected)}) - {'通过' if result == expected else '失败'}")

        # 测试4: 两种乘法实现的一致性
        a, b = 0x1234567890abcdef, 0xfedcba0987654321
        result1 = GF128.mul(a, b)
        result2 = GF128.mul_alt(a, b)
        print(f"方法1: {hex(result1)}")
        print(f"方法2: {hex(result2)}")
        print(f"是否相等: {'是' if result1 == result2 else '否'}")

        # 测试5: 乘法结合律
        a, b, c = 0x1234, 0x5678, 0x9abc
        left = GF128.mul(GF128.mul(a, b), c)
        right = GF128.mul(a, GF128.mul(b, c))
        print(f"(a*b)*c = {hex(left)}")
        print(f"a*(b*c) = {hex(right)}")
        print(f"是否相等: {'是' if left == right else '否'}")

        # 测试6: 分配律
        left = GF128.mul(a, GF128.add(b, c))
        right = GF128.add(GF128.mul(a, b), GF128.mul(a, c))
        print(f"a*(b+c) = {hex(left)}")
        print(f"a*b + a*c = {hex(right)}")
        print(f"是否相等: {'是' if left == right else '否'}")

    @staticmethod
    def test_inverse():
        """测试逆元计算"""
        print("\n[GF128测试] 测试逆元计算...")

        # 测试1: 1的逆元是1
        inv = GF128.inverse(1)
        print(f"1的逆元 = {hex(inv)} (期望: 0x1) - {'通过' if inv == 1 else '失败'}")

        # 测试2: 简单数的逆元
        # 在GF(2^128)中，2的逆元可以通过计算得到
        x = 0x2
        inv = GF128.inverse(x)
        check = GF128.mul(x, inv)
        print(f"2的逆元 = {hex(inv)}")
        print(f"2 * 逆元 = {hex(check)} (期望: 0x1) - {'通过' if check == 1 else '失败'}")

        # 测试3: 使用已知的H值
        H = 0xa6c1c472c104053302ff436385112158
        print(f"\n测试H = {hex(H)}")

        inv = GF128.inverse(H)
        print(f"H的逆元 = {hex(inv)}")

        check = GF128.mul(H, inv)
        print(f"H * 逆元 = {hex(check)} (期望: 0x1) - {'通过' if check == 1 else '失败'}")

        # 测试4: 幂运算的一致性
        H_sq = GF128.mul(H, H)
        H_sq_pow = GF128.power(H, 2)
        print(f"\nH^2 (乘法): {hex(H_sq)}")
        print(f"H^2 (幂运算): {hex(H_sq_pow)}")
        print(f"是否相等: {'是' if H_sq == H_sq_pow else '否'}")

    @staticmethod
    def test_division():
        """测试除法"""
        print("\n[GF128测试] 测试除法...")

        a = 0x1234567890abcdef
        b = 0x2

        # a / b = a * b^{-1}
        quotient = GF128.div(a, b)
        check = GF128.mul(quotient, b)
        print(f"a / b = {hex(quotient)}")
        print(f"(a / b) * b = {hex(check)} (期望: {hex(a)}) - {'通过' if check == a else '失败'}")

    @staticmethod
    def test_special_values():
        """测试特殊值"""
        print("\n[GF128测试] 测试特殊值...")

        x = 0xa6c1c472c104053302ff436385112158

        # 0 * x = 0
        result = GF128.mul(0, x)
        print(f"0 * x = {hex(result)} (期望: 0x0) - {'通过' if result == 0 else '失败'}")

        # 1 * x = x
        result = GF128.mul(1, x)
        print(f"1 * x = {hex(result)} (期望: {hex(x)}) - {'通过' if result == x else '失败'}")

        # x * 0 = 0
        result = GF128.mul(x, 0)
        print(f"x * 0 = {hex(result)} (期望: 0x0) - {'通过' if result == 0 else '失败'}")

        # x * 1 = x
        result = GF128.mul(x, 1)
        print(f"x * 1 = {hex(result)} (期望: {hex(x)}) - {'通过' if result == x else '失败'}")

    @staticmethod
    def run_all_tests():
        """运行所有测试"""
        print("===== 开始GF(2^128)运算测试 =====")

        GF128.test_multiplication()
        GF128.test_inverse()
        GF128.test_division()
        GF128.test_special_values()

        print("===== GF(2^128)运算测试结束 =====")


# 当直接运行此文件时执行测试
if __name__ == "__main__":
    GF128.run_all_tests()