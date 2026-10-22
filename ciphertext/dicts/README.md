# 密文字典匹配本地字典

把 UTF-8 `.txt` 字典文件放在此目录。每行写一个候选明文；文件会按相对路径的字母顺序依次处理，因此可用 `00-`、`10-` 等前缀安排由易到难的顺序。

打开 `ciphertext/index.html` 后，在浏览器中选择此目录。出于浏览器的本地文件安全限制，网页不能静默读取同目录文件；选择目录会明确授权本次读取。

此目录不附带大型或来源不明的字典文件。

支持 MD5、SHA-1、SHA-256、SHA-384、SHA-512、bcrypt（$2a$/$2b$/$2y$）和 Django 格式 PBKDF2-SHA256 的字典匹配。bcrypt.js 浏览器实现及其 BSD 许可证见 `bcrypt-source.js` 与 `BCRYPT-LICENSE.txt`。
