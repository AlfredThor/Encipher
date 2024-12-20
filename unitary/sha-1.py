import hashlib


class Main:

    def calculate_sha1(self, data):
        """计算数据的 SHA-1 哈希值"""
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data.encode('utf-8'))  # 必须编码为字节
        return sha1_hash.hexdigest()

    def calculate_file_sha1(self, filepath):
        try:
            with open(filepath, 'rb') as f:  # 以二进制模式读取文件
                sha1_hash = hashlib.sha1()
                for chunk in iter(lambda: f.read(4096), b""):  # 分块读取大文件
                    sha1_hash.update(chunk)
                return sha1_hash.hexdigest()
        except FileNotFoundError:
            return "File not found."


main = Main()

if __name__ == '__main__':
    code1 = main.calculate_sha1("hello")
    code2 = main.calculate_sha1("Hello")
    print(code1)
    print(code2)
    '''
        大小写敏感,哈希值不同!
        aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
    '''
    file_code = main.calculate_file_sha1('/Users/Alfred/PycharmProjects/Encipher/files/python-3.12.3-macos11.pkg')
    print(file_code)
    '''
        840651f6d6915dd8782c67d38dff30a935499515
    '''