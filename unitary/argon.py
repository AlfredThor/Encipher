from argon2 import Type
from argon2 import PasswordHasher, exceptions


class Main:
    def hash_password(self, password):
        """使用 Argon2 哈希密码"""
        ph = PasswordHasher()
        try:
            hashed_password = ph.hash(password)
            return hashed_password
        except exceptions.HashingError as e:
            print(f"哈希密码时出错：{e}")
            return None

    def verify_password(self, password, hashed_password):
        """验证密码是否与哈希值匹配"""
        ph = PasswordHasher()
        try:
            is_valid = ph.verify(hashed_password, password)
            return is_valid
        except exceptions.VerifyMismatchError:
            return False  # 密码不匹配
        except exceptions.InvalidHash as e:
            print(f"无效的哈希值：{e}")
            return False
        except exceptions.VerificationError as e:
            print(f"验证时出错：{e}")
            return False

    # 使用不同的 Argon2 类型 (Argon2id 是推荐的类型)
    def hash_password_with_type(self, password, type):
        ph = PasswordHasher(type=type)
        try:
            hashed_password = ph.hash(password)
            return hashed_password
        except exceptions.HashingError as e:
            print(f"哈希密码时出错：{e}")
            return None

    def weak_hash(self):
        # 不安全的例子：使用过低的参数
        ph_weak = PasswordHasher(time_cost=1, memory_cost=8192)  # 非常弱！
        weak_hash = ph_weak.hash("password")
        print(f"弱 Argon2 哈希值：{weak_hash}")

    def ph_id(self):
        # 推荐使用 Type.ID (Argon2id)
        ph_id = PasswordHasher(type=Type.ID)
        hashed_id = ph_id.hash("password")
        print(f"使用 Argon2id 的哈希值：{hashed_id}")



main = Main()

if __name__ == '__main__':

    # 示例
    password = "mysecretpassword"
    hashed = main.hash_password(password)

    if hashed:
        print(f"密码 '{password}' 的 Argon2 哈希值：{hashed}")

        if main.verify_password(password, hashed):
            print("密码验证成功！")
        else:
            print("密码验证失败。")

        wrong_password = "wrongpassword"
        if main.verify_password(wrong_password, hashed):
          print("使用错误密码验证成功，这是一个安全漏洞！") # 不应该发生
        else:
          print("使用错误密码验证失败，符合预期。")

    else:
      print("哈希失败")

    hashed_id = main.hash_password_with_type(password, Type.ID)
    if hashed_id:
        print(f"密码 '{password}' 的 Argon2id 哈希值：{hashed_id}")

    main.weak_hash()
    main.ph_id()