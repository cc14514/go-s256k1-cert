# s256k1 cert example

>目前 `golang crypto/x509` 这个库针对 `ECC` 的密钥只支持 `P224 / P256 / P384 / P521` 这四条曲线，
>区块链开发通常使用 `secp256k1` 曲线，也不只是 golang 不支持这条曲线，貌似目前能够直接支持使用
>这条曲线生成密钥和数字证书的就只有 `libssl.so` 这个库，当我们想要为 `secp256k1` 密钥签发证书时可以选择在 `go` 中引用 `libssl.so` 
>也可以选择直接使用 `openssl` ，本例提供了更为优雅的第三种选择，使用 [`PDXBaap/go-std-ext` (`PDX` 官方提供的 `golang` 标准库扩展)](http://www.github.com/PDXbaap/go-std-ext) 
>实现让 `x509` 库直使用 `ECC secp256k1` 密钥生成和验证证书；

## 安装 PDXBaap/go-std-ext

假设本地已经安装了 `go1.14.4` 开发环境

```bash
$> go get -v -u github.com/PDXbaap/go-std-ext
...

$> go-std-ext
GOROOT :  /usr/local/go/src
VERSION :  go version go1.14.4 darwin/amd64
Success.
```

## 使用

通过以上步骤安装 `go-std-ext` 成功以后，可以直接使用标准库生成 `ECC secp256k1` 密钥

```go
// 生成 ecc secp256k1 密钥
caPrivkey, _ := ecdsa.GenerateKey(elliptic.S256(), rand.Reader)
```

其中 `elliptic.S256()` 对应的即为 `secp256k1` 曲率，这个 `ECC` 密钥可以直接拿来创建 `x509` 证书

```go
userPrv, _ := ecdsa.GenerateKey(elliptic.S256(), rand.Reader)
certTemplate := &x509.Certificate{ ... }
...
// 为 ecc secp256k1 公钥签发 x509 数字证书
certBuf, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, userPrv.Public(), caPrivkey)
...
```

生成 `S256` 密钥

```go
// 创建一个 ECC S256K1 私钥，用于生成证书，以 PEM 格式返回
func (self *ECCKeytool) GenKey(pwd string) (privRaw, pubRaw []byte) {
	priv, _ := ecdsa.GenerateKey(elliptic.S256(), rand.Reader)
	bpriv, _ := x509.MarshalECPrivateKey(priv)
	pemblock, _ := x509.EncryptPEMBlock(rand.Reader, self.keyTitle, bpriv, []byte(pwd), self.agl)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemblock)
	privRaw = buf.Bytes()
	pubRaw = self.exportRawPubkey(priv.Public())
	return
}
...
prv, pub := kt.GenKey(pwd)
fmt.Println(string(prv))
fmt.Println(string(pub))
...
// 输出 :
-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,b042a7ac9e3b1538e259d066bd59c970

WKK7my+sZwn5vpYQOzouSqE4iapa9L784rDAqy6oLXBLN2WjUuzW5wTEd4NI6Iwk
+fjAheqdfvvw/4ar7kCqOkOStQlJPOst3jhdwggR7JxDHtzCNasyEqgy8Sl3r6Ku
TS9xYQqdLozwxlkwGoyLbrE7NMBdONmptqh8xTukEhE=
-----END ECC PRIVATE KEY-----

-----BEGIN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQgDQgAE6X3xzqnv6H6r1d/gE8UTfkzF7xZv
19NuhTfYrWtz++pIU6wRId75XDnCfj/oBM6Ujmq3leorS6HEJEX+0B7DmQ==
-----END ECC PUBLIC KEY-----
```

签发数字证书

```go
func (self *ECCKeytool) GenCertForPubkey(prvkey *ecdsa.PrivateKey, caCert *x509.Certificate, userPubkey crypto.PublicKey, subject *Subject) []byte {
	id := new(big.Int).SetBytes(uuid.NewV4().Bytes())
	// 生成 CRT
	certTemplate := &x509.Certificate{
		Subject:        subject.tox(),
		SerialNumber:   id,                                        // 序列号
		NotBefore:      time.Now(),                                // 在此之前无效
		NotAfter:       time.Now().Add(10 * 365 * 24 * time.Hour), // 在此之后无效
		EmailAddresses: []string{subject.Email},
	}
  ...
}
...
userCertPem := kt.GenCertForPubkey(caPrv, caCert, upub, &Subject{
	Country:            "中国",
	OrganizationalUnit: "上海滩",
	Organization:       "精武门",
	CommonName:         "陈真",
	Email:              "cc14514@icloud.com",
})
fmt.Println(string(userCertPem))
...
// 输出：
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRALb2OkuR006trjWoL4FUHyEwCgYIKoZIzj0EAwIwSjEP
MA0GA1UEBgwG5Lit5Zu9MQ8wDQYDVQQKDAbnu4Tnu4cxFTATBgNVBAsMDOe7hOe7
h+WNleS9jTEPMA0GA1UEAwwG5L2g5aW9MB4XDTIwMDcxMzA5MzgzM1oXDTMwMDcx
MTA5MzgzM1owRzEPMA0GA1UEBgwG5Lit5Zu9MRIwEAYDVQQKDAnnsr7mrabpl6gx
DzANBgNVBAsMBuaxn+a5ljEPMA0GA1UEAwwG6ZmI55yfMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQgDQgAEbt0XrE9t2HRud+OiAtl0hRgS9oBVAgkcsPy4fb/4BBFVqwWD
L7gbgMMe4FjhSVC29RDfz0nXYjql4lsjv0Z2aaMpMCcwDgYDVR0PAQH/BAQDAgSw
MBUGA1UdEQQOMAyBCmN6QGp3bS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgXQX8RaQ7
38TVGFm9/znBKU8sxhUuT9Bzs76AsKUKmUECIQC/2m8CrHC7Eox+712dazFaDvs6
DCigEm+k6VeDG+brCg==
-----END CERTIFICATE-----
```

以上样例代码都可以在 [`s256k1_cert.go`](https://github.com/cc14514/go-s256k1-cert) 中获得 , 并可以通过 [`s256k1_cert_test.go`](https://github.com/cc14514/go-s256k1-cert) 进行测试，其中包含了密钥和证书的生成与验证；

注意：对于 `crypto` 的扩展将从 `go1.14.4` 开始迭代, [`PDXBaap/go-std-ext`](http://www.github.com/PDXbaap/go-std-ext) 会在每次 `golang` 发布新版本时一同更新，
如果您无法安装请及时更新本地的 `golang` 开发环境

特别注意：安装时 `GOROOT/src` 目录将会被改写，权限根据用户和组进行判断，所以最好将此目录所有权修改为当前用户，
例如 `chown -R {CURRENT_USER}:{CURRENT_GROUP} {GOROOT}/src`
