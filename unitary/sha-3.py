import hashlib


class Main:
    def calculate_sha3_256(self, data):
        """计算数据的 SHA3-256 哈希值"""
        sha3_hash = hashlib.sha3_256()
        sha3_hash.update(data.encode('utf-8'))  # 必须编码为字节
        return sha3_hash.hexdigest()

    def calculate_sha3_512(self, data):
        """计算数据的 SHA3-512 哈希值"""
        sha3_hash = hashlib.sha3_512()
        sha3_hash.update(data.encode('utf-8'))
        return sha3_hash.hexdigest()

    def calculate_shake_128(self, data, length):
        """计算数据的 SHAKE128 可变长度哈希值"""
        shake_hash = hashlib.shake_128()
        shake_hash.update(data.encode('utf-8'))
        return shake_hash.hexdigest(length) # SHAKE 需要指定输出长度

    # 文件哈希计算示例
    def calculate_file_sha3_256(self, filepath):
        try:
            with open(filepath, 'rb') as f:  # 以二进制模式读取文件
                sha3_hash = hashlib.sha3_256()
                for chunk in iter(lambda: f.read(4096), b""):  # 分块读取大文件
                    sha3_hash.update(chunk)
                return sha3_hash.hexdigest()
        except FileNotFoundError:
            return "File not found."

main = Main()

if __name__ == '__main__':

    # 示例
    data = "hello"

    sha3_256_hash = main.calculate_sha3_256(data)
    print(f"'{data}' 的 SHA3-256 哈希值：{sha3_256_hash}")
    # 'hello' 的 SHA3-256 哈希值：3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392

    sha3_512_hash = main.calculate_sha3_512(data)
    print(f"'{data}' 的 SHA3-512 哈希值：{sha3_512_hash}")
    # 'hello' 的 SHA3-512 哈希值：75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976

    shake_128_hash = main.calculate_shake_128(data, 32) # 输出 32 字节（64 个十六进制字符）
    print(f"'{data}' 的 SHAKE128 哈希值 (32 字节)：{shake_128_hash}")
    # 'hello' 的 SHAKE128 哈希值 (32 字节)：8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463

    file_path = "/Users/Alfred/PycharmProjects/Encipher/files/python-3.12.3-macos11.pkg"  # 请替换为你的文件路径
    file_hash = main.calculate_file_sha3_256(file_path)
    print(f"文件 '{file_path}' 的 SHA3-256 哈希值：{file_hash}")
    # 文件 '/Users/Alfred/PycharmProjects/Encipher/files/python-3.12.3-macos11.pkg' 的 SHA3-256 哈希值：44b95eca949647dc847ca8b55281e9490bae1224f2c743fea1966543d8640d27