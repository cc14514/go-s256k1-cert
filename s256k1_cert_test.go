package example

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

var (
	pwd      = "123456"
	caKeyPem = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,a253c18bb0a4d099e27b6294a840eecd

xgCvhe9ig93vx1cupvvBnRI3olwWAa5SpBzD2+bw9P50JWpM5aJTSKsCNoZBitJQ
fPUraQmQmgzNOshFOgXDCTCQRLppIidPpbYO7tbezMJK9tl1v2XwUO3VETySZH+S
9xDeXlAHHmuRpjLR3ATYrp3v1MKJWsUtSAaU22DdddI=
-----END ECC PRIVATE KEY-----

-----BEGIN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQgDQgAE/ePSyLE7+hGx/bhNp3wkzNKu3u0R
QppfTzILmdlBRIHGlr/zBzzksz4LnbpOfg5i3cjO8eWYwwkTbAkfaEV9vw==
-----END ECC PUBLIC KEY-----
`
	caCertPem = `-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIQAIfBK10cTFa2cJGe3TycijAKBggqhkjOPQQDAjBKMQ8w
DQYDVQQGDAbkuK3lm70xDzANBgNVBAoMBue7hOe7hzEVMBMGA1UECwwM57uE57uH
5Y2V5L2NMQ8wDQYDVQQDDAbkvaDlpb0wHhcNMjAwNzEzMDg0MTMyWhcNMzAwNzEx
MDg0MTMyWjBKMQ8wDQYDVQQGDAbkuK3lm70xDzANBgNVBAoMBue7hOe7hzEVMBMG
A1UECwwM57uE57uH5Y2V5L2NMQ8wDQYDVQQDDAbkvaDlpb0wWTATBgcqhkjOPQIB
BggqhkjOPQMBCANCAAT949LIsTv6EbH9uE2nfCTM0q7e7RFCml9PMguZ2UFEgcaW
v/MHPOSzPguduk5+DmLdyM7x5ZjDCRNsCR9oRX2/o0IwQDAOBgNVHQ8BAf8EBAMC
AZYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHREEFjAUgRJjYzE0NTE0QGljbG91ZC5j
b20wCgYIKoZIzj0EAwIDSAAwRQIhAPe1J+cH7kSfCvrAesLewKLG+dRrwtbtwnsa
3qKFMzMDAiAw89EB0X6lij2/3f31lzb0GDWYeL53LcJbwD828Q7Rzw==
-----END CERTIFICATE-----
`

	userKeyPem = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3399785f0aa46d0a75562a458d96eaa6

kfzLHj85tX/3YMxiSsvL+yte7SgESxJrhN7ZmThRevI/v3MqW6jZ4xmlu2Nt72HI
i8VZKiY5ey9X4jzKddB4ylWBaabbdBNQVPSOj2byV9xwmhC/W4JYsfrRVG9JO0Ea
6OJyZL435MRJL7SdotGJHhdZooPsddz63NwqcvAj5ZM=
-----END ECC PRIVATE KEY-----

-----BEGIN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQgDQgAEJC15ckFw+3jJNyj1IqhqCz4/9X9b
cn4e47nSrvUiENL76YbmlqsCE1NZl/Xq+2jdsTnohXvyVp3czAFRjXJOqg==
-----END ECC PUBLIC KEY-----
`
	userCertPem = `-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRANTNfKSeJU27kYfEwGErb+swCgYIKoZIzj0EAwIwSjEP
MA0GA1UEBgwG5Lit5Zu9MQ8wDQYDVQQKDAbnu4Tnu4cxFTATBgNVBAsMDOe7hOe7
h+WNleS9jTEPMA0GA1UEAwwG5L2g5aW9MB4XDTIwMDcxMzA4NDIwNFoXDTMwMDcx
MTA4NDIwNFowRzEPMA0GA1UEBgwG5Lit5Zu9MRIwEAYDVQQKDAnnsr7mrabpl6gx
DzANBgNVBAsMBuaxn+a5ljEPMA0GA1UEAwwG6ZmI55yfMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQgDQgAELN9p1GePslXHF9VM9FMrp3LQJxj5NRqBwjr4+zxeSOpFYfd1
i9NSov2o0XqA+5zt9uqEnJZ6ehNM7iK5yghsP6MpMCcwDgYDVR0PAQH/BAQDAgSw
MBUGA1UdEQQOMAyBCmN6QGp3bS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgKLcu0UqM
VSotaUQN7tjamE+PLJBVt9auTD62wLXJYHQCIDObfn2caWjtWSuJprDP1Huaxf5s
pfxJyzNEIQ+AHKR9
-----END CERTIFICATE-----
`
	kt          = NewKeytool()
	prvkeyByPem = func(keyPem, pwd string) *ecdsa.PrivateKey {
		prvBlk, _ := pem.Decode([]byte(keyPem))
		prvBuf, err := x509.DecryptPEMBlock(prvBlk, []byte(pwd))
		if err != nil {
			panic(err)
		}
		prv, err := x509.ParseECPrivateKey(prvBuf)
		if err != nil {
			panic(err)
		}
		return prv
	}
)

// 创建一个 ECC S256K1 私钥，用于生成证书，以 PEM 格式返回
func TestECCKeytool_GenKey(t *testing.T) {
	prv, pub := kt.GenKey(pwd)
	fmt.Println(string(prv))
	fmt.Println(string(pub))
}

func TestECCKeytool_GenCertForPubkeyForCA(t *testing.T) {
	prv := prvkeyByPem(caKeyPem, pwd)
	caCert := kt.GenCertForPubkey(prv, nil, prv.Public(), &Subject{
		Country:            "中国",
		OrganizationalUnit: "组织单位",
		Organization:       "组织",
		CommonName:         "你好",
		Email:              "cc14514@icloud.com",
	})
	fmt.Println(string(caCert))
}

func TestECCKeytool_GenCertForPubkeyForUser(t *testing.T) {
	userPrv, userPub := kt.GenKey(pwd)
	// 输出用户密钥 >>>>>>>>
	fmt.Println(string(userPrv))
	fmt.Println(string(userPub))
	// 输出用户密钥 <<<<<<<<

	// 解析 PEM 公钥 >>>>>>
	userPubBlk, _ := pem.Decode(userPub)
	ipub, err := x509.ParsePKIXPublicKey(userPubBlk.Bytes)
	if err != nil {
		panic(err)
	}
	upub := ipub.(crypto.PublicKey)
	t.Log("user pubkey :", upub)
	// 解析 PEM 公钥 <<<<<<

	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 >>>>
	caCertBlk, _ := pem.Decode([]byte(caCertPem))
	caCert, err := x509.ParseCertificate(caCertBlk.Bytes)
	if err != nil {
		panic(err)
	}
	caPrv := prvkeyByPem(caKeyPem, pwd)

	userCertPem := kt.GenCertForPubkey(caPrv, caCert, upub, &Subject{
		Country:            "中国",
		OrganizationalUnit: "江湖",
		Organization:       "精武门",
		CommonName:         "陈真",
		Email:              "cz@jwm.com",
	})
	fmt.Println(string(userCertPem))
	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 <<<<
}

func TestVerifyUserCert(t *testing.T) {
	// 加载用户证书 >>>>
	userCertBlk, _ := pem.Decode([]byte(userCertPem))
	userCert, err := x509.ParseCertificate(userCertBlk.Bytes)
	if err != nil {
		panic(err)
	}
	// 加载用户证书 <<<<

	// 加载 CA 证书 >>>>
	caCertBlk, _ := pem.Decode([]byte(caCertPem))
	caCert, err := x509.ParseCertificate(caCertBlk.Bytes)
	if err != nil {
		panic(err)
	}
	// 加载 CA 证书 <<<<

	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	opts.Roots.AddCert(caCert)

	// 使用证书链来验证证书 >>>>
	ret, err := userCert.Verify(opts)
	fmt.Println("keychain verify : ", err, ret)
	// 使用证书链来验证证书 <<<<

	// 验证父证书签名 >>>>
	err = userCert.CheckSignatureFrom(caCert)
	fmt.Println(caCert.IsCA)
	fmt.Println("check sign :", err)
	// 验证父证书签名 <<<<

}
