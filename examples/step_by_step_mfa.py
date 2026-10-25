"""Drive every step yourself, e.g. from a chat bot that relays codes and QR images."""

import getpass

from nwafu_cas import CasClient

cas = CasClient()
res = cas.login(input("学号/工号: "), getpass.getpass("密码: "))
while not res.done:
    mfa = res.mfa
    for i, m in enumerate(mfa.supported, 1):
        print(i, m.name, m.kind)
    m = mfa.supported[int(input("选择: ")) - 1]
    mfa.select(m.type)
    if m.kind == "code":
        print(mfa.send_code())
        res = mfa.submit(code=input("验证码: "))
    elif m.kind == "otp":
        res = mfa.submit(code=input("安全令牌: "))
    elif m.kind == "password":
        res = mfa.submit(password=getpass.getpass("密码: "))
    else:
        qr = mfa.start_qr()
        open(f"qr.{qr.image_type}", "wb").write(qr.image)
        print(f"请{qr.hint}，二维码已保存到 qr.{qr.image_type}")
        res = qr.wait(on_status=print)
print("登录成功", res.response.url)
cas.save("state.json")
