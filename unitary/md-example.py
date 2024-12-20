import hashlib
from pprint import pprint


class Main:

    def encrypt(self, password):
        md5_hash = hashlib.md5()
        md5_hash.update(password.encode('utf-8'))
        hash_result = md5_hash.hexdigest()
        return hash_result

    def collision(self):
        '''ChatGPT给出的碰撞示例,但是测试不通过'''
        value1 = bytes.fromhex(
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89" +
            "55ad340609f4b30283e488832571415a08d661cfeb862344d6e19bf8c9c1f8f4" +
            "275530418a8d6e039b156c3f29b33168d13e4449d1f0259265ed7d4bbde6d36a" +
            "00835d7c5e363d5f8abdb779db6b0e845aba46543cb833b1232078d50a361dba"
        )
        value2 = bytes.fromhex(
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89" +
            "55ad340609f4b30283e488832571415a08d661cfeb862344d6e19bf8c9c1f8f4" +
            "275530418a8d6e039b156c3f29b33168d13e4449d1f0259265ed7d4bbde6d36a" +
            "00835d7c5e363d5f8abdb779db6b0e845aba46543cb833b1232078d50a361dbb"
        )
        md5_1 = hashlib.md5(value1).hexdigest()
        md5_2 = hashlib.md5(value2).hexdigest()

        return {'Value 1 MD5': md5_1, 'Value 2 MD5': md5_2}

    def calculate_file_md5(self, filepath):
        try:
            with open(filepath, 'rb') as f:  # 二进制模式读取文件
                md5_hash = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):  # 分块读取大文件
                    md5_hash.update(chunk)
                return md5_hash.hexdigest()
        except FileNotFoundError:
            return "File not found."


main = Main()


if __name__ == '__main__':
    code = main.encrypt('alfred85613')
    print(code)
    # 594351431d459972e66afd1958bb0c5a

    collision = main.collision()
    print(collision)
    print(f"MD5 Collided: {collision['Value 1 MD5'] == collision['Value 2 MD5']}")
    '''
        {'Value 1 MD5': 'e8a1c38be045180868340d25235e55cf', 'Value 2 MD5': '670655a809fde5e101cc3d42801d5d60'}
        MD5 Collided: False
    '''

    file_code = main.calculate_file_md5('/Users/Alfred/PycharmProjects/Encipher/files/python-3.12.3-macos11.pkg')
    print(file_code)
    # 6114a3bb9b288f23ab38dbbb959be1bf