# pairwise-dns-guard

图片抓取服务允许用户填 URL 后，DNS 重绑定就能把请求送进内网：校验时解析到公网 IP，真正请求时 TTL 到期换成 `127.0.0.1`；CNAME 链最后指向内网段；十进制和八进制 IP 绕过点分十进制判断；IPv6 映射地址没有归一；只校验第一次解析结果，连接时重新解析；302 跳转后不复查目标；代理配置让请求走内网出口；解析结果缓存没有绑定连接；DNS 响应里的多答案只取第一个；空 host 回落到本机。security/dns_guard.py 是核心，tests/test_dns_guard.py 15个红。要修的是：解析与连接绑定；TTL 期间复用同一 IP；CNAME 逐跳校验；非标准 IP 归一；IPv6 映射检查；跳转逐跳复查；禁代理回退；缓存键含 host；全部答案校验；空 host 拒绝。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
