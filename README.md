# clashmask

一个可逆的 Clash 配置脱敏工具（Go 实现，跨平台）。

特点：
- 保留原始文本风格：按行处理，不做整体 YAML 重排，尽量不破坏注释和尾注释。
- 同时处理 YAML / JSON 风格键值。
- 支持 URI 形式节点中的 host 和协议凭据脱敏。
- 通过映射文件可一键还原原始内容。

## 1. 构建

```bash
go build -o clashmask .
```

## 2. 脱敏

```bash
./clashmask mask -in ./config.yaml -out ./config.masked.yaml -map ./config.maskmap.json
```

也可以原地替换：

```bash
./clashmask mask -in ./config.yaml -in-place -map ./config.maskmap.json
```

## 3. 还原

```bash
./clashmask unmask -in ./config.masked.yaml -out ./config.restored.yaml -map ./config.maskmap.json
```

原地还原：

```bash
./clashmask unmask -in ./config.masked.yaml -in-place -map ./config.maskmap.json
```

## 4. 默认替换字段

- host 类：`server, host, hostname, sni, servername, server_name, peer, endpoint, domain, address`
- secret 类：`password, passwd, pass, uuid, private-key, private_key, psk, auth, auth-str, auth_str, obfs-password, obfs_password, token, secret`

可自定义：

```bash
./clashmask mask \
  -in ./config.yaml \
  -host-keys "server,host,sni,peer" \
  -secret-keys "password,uuid,private-key,token"
```

## 5. 推到 GitHub

```bash
git init
git add .
git commit -m "feat: add reversible clash profile desensitizer"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

建议把映射文件加入 `.gitignore`，避免把可还原的敏感映射公开。
