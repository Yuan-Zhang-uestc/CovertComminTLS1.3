"""
线性方程组求解模块（改编自Java代码）
使用分数运算确保精确求解
"""
from fractions import Fraction
import numpy as np

from gf128 import GF128


class SolveMatBigInt:
    """使用高斯消元法求解线性方程组（使用分数运算）"""

    @staticmethod
    @staticmethod
    def solve_gf128(A, b):
        """
        在GF(2^128)上求解线性方程组 Ax = b
        简化版本：假设有2个方程，m个未知数
        """
        # 这里我们简化处理，因为通常m=2
        # 对于2个方程的情况，我们可以直接求解

        # 将GF(2^128)元素转换为整数
        A_int = [[int(elem) for elem in row] for row in A]
        b_int = [int(elem) for elem in b]

        # 对于2x2系统，直接求解
        if len(A) == 2 and len(A[0]) == 2:
            a, b_coef = A_int[0][0], A_int[0][1]
            c, d = A_int[1][0], A_int[1][1]
            e, f = b_int[0], b_int[1]

            # 在GF(2^128)上求解
            # 需要实现GF(2^128)上的除法和逆元
            # 这里简化：假设矩阵可逆

            # 计算行列式
            det = GF128.multiply(a, d) ^ GF128.multiply(b_coef, c)

            if det == 0:
                print("矩阵不可逆")
                return None

            # 计算逆矩阵
            det_inv = GF128.inverse(det)

            # 计算解
            x1 = GF128.multiply(d, e) ^ GF128.multiply(b_coef, f)
            x1 = GF128.multiply(x1, det_inv)

            x2 = GF128.multiply(a, f) ^ GF128.multiply(c, e)
            x2 = GF128.multiply(x2, det_inv)

            return [x1, x2]
        else:
            # 对于更大的系统，使用高斯消元法
            n = len(A[0])
            m = len(A)

            # 构建增广矩阵
            augmented = [row[:] + [b_val] for row, b_val in zip(A_int, b_int)]

            # 高斯消元法
            row = 0
            for col in range(n):
                # 寻找主元
                pivot = None
                for i in range(row, m):
                    if augmented[i][col] != 0:
                        pivot = i
                        break

                if pivot is None:
                    continue

                # 交换行
                augmented[row], augmented[pivot] = augmented[pivot], augmented[row]

                # 归一化主元行
                pivot_val = augmented[row][col]
                if pivot_val != 1:
                    pivot_inv = GF128.inverse(pivot_val)
                    for j in range(col, n + 1):
                        augmented[row][j] = GF128.multiply(augmented[row][j], pivot_inv)

                # 消去其他行
                for i in range(m):
                    if i != row and augmented[i][col] != 0:
                        factor = augmented[i][col]
                        for j in range(col, n + 1):
                            term = GF128.multiply(factor, augmented[row][j])
                            augmented[i][j] = GF128.multiply(augmented[i][j], term)

                row += 1
                if row >= m:
                    break

            # 提取解
            x = [0] * n
            for i in range(min(m, n)):
                if augmented[i][i] != 0:
                    x[i] = augmented[i][n]

            return x

    @staticmethod
    def solve_rational(A, b):
        """
        在有理数域上求解线性方程组（精确分数运算）
        A: 系数矩阵 (m x n)，元素为整数
        b: 常数向量 (m)，元素为整数
        返回: 解向量，Fraction对象列表
        """
        m = len(A)
        n = len(A[0])

        # 转换为分数
        A_frac = [[Fraction(val) for val in row] for row in A]
        b_frac = [Fraction(val) for val in b]

        # 创建增广矩阵
        augmented = [row[:] + [b_val] for row, b_val in zip(A_frac, b_frac)]

        # 前向消元
        for col in range(n):
            # 寻找主元
            pivot_row = None
            for row in range(col, m):
                if augmented[row][col] != 0:
                    pivot_row = row
                    break

            if pivot_row is None:
                continue

            # 交换行
            augmented[col], augmented[pivot_row] = augmented[pivot_row], augmented[col]

            # 归一化主元行
            pivot = augmented[col][col]
            for j in range(col, n + 1):
                augmented[col][j] /= pivot

            # 消去其他行
            for i in range(m):
                if i != col and augmented[i][col] != 0:
                    factor = augmented[i][col]
                    for j in range(col, n + 1):
                        augmented[i][j] -= factor * augmented[col][j]

        # 提取解
        solution = []
        for i in range(n):
            if i < m and augmented[i][i] != 0:
                solution.append(augmented[i][n])
            else:
                solution.append(Fraction(0))

        return solution

    @staticmethod
    def verify_solution(A, b, x):
        """验证解是否正确"""
        m = len(A)
        n = len(A[0])

        for i in range(m):
            lhs = sum(A[i][j] * x[j] for j in range(n))
            if lhs != b[i]:
                return False
        return True