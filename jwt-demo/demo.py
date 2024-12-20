import jwt
from passlib.context import CryptContext
from datetime import timezone, timedelta, datetime


class Permissions():
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
    secret = '695258412564125'

    # 密码加密
    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    # 密码校验
    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    # token生成
    def encode_token(self, id, minutes=10080):
        now_time = datetime.now(timezone.utc)
        payload = {
            'exp': now_time + timedelta(days=0, minutes=1), # 超时时间
            'iat': now_time,
            'sub': id  # 自定义用户ID
        }
        token = jwt.encode(payload, self.secret, algorithm='HS256')
        return token if isinstance(token, str) else token.decode('utf-8')

    # token 解码
    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return {'code':200, 'user_id':payload['sub']}
        except jwt.ExpiredSignatureError:
            return {'code': 400, 'message': 'Token超期！'}
        except jwt.InvalidTokenError as e:
            return {'code': 400, 'message': '非法的token！'}


permissions = Permissions()

if __name__ == '__main__':
    code = permissions.encode_token('98')
    print(code)
    print(permissions.decode_token(code))