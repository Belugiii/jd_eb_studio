# EB Studio

用于生成和解密京东收银商户 **eb** 参数。

## 算法

- AES/CBC/PKCS5Padding
- 默认密钥（hex）：`39323332393637333930303832363137`
- 固定 IV：`0102030405060708`
- 密文输出为大写十六进制

## 启动

```bash
pip3 install --break-system-packages -r requirements.txt
python3 app.py
```

## 功能

- 明文 JSON / 文本生成 eb 密文
- 密文解密回 UTF-8 明文（JSON 自动格式化）
- 可修改 AES 密钥，IV 与源码保持一致
