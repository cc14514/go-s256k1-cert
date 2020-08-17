package example

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"testing"
	"time"
)

var (
	pwd      = "123456"
	caKeyPem = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,57600d03c7bc2b496c3e301ad1037b89

8EoWxS2hyM9ftM8Q4R7vM3zuMt2q8QpiFP7irOY9jgmSSHBDO21uDyW93V+59O8c
6UR9NpNi8F0w5lP4xXkjdtDb6S25tEitrPMBGWnbnIGkqrUl1PLXa9dLtRxVMxYM
IJfC9eLFFIqcQVAEU6VJ2tD7oikFd89/RhZQ9F5rVFs=
-----END ECC PRIVATE KEY-----

-----BEGIN ECC PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUQMFuiWK6enMEZuGr7yoMXxaJ2OF42be
ufKu/XTDIwNEFjf64iaTgdlfinWQ1fcRQOypoyEulQhSjxw0E8Nauw==
-----END ECC PUBLIC KEY-----
`
	caCertPem = `-----BEGIN CERTIFICATE-----
MIIB0TCCAXigAwIBAgIRANz9PDono0ejr34Uad02c+MwCgYIKoZIzj0EAwIwSjEP
MA0GA1UEBgwG5Lit5Zu9MQ8wDQYDVQQKDAbnu4Tnu4cxFTATBgNVBAsMDOe7hOe7
h+WNleS9jTEPMA0GA1UEAwwG5L2g5aW9MB4XDTIwMDcxNzA1MjcyNloXDTMwMDcx
NTA1MjcyNlowSjEPMA0GA1UEBgwG5Lit5Zu9MQ8wDQYDVQQKDAbnu4Tnu4cxFTAT
BgNVBAsMDOe7hOe7h+WNleS9jTEPMA0GA1UEAwwG5L2g5aW9MFYwEAYHKoZIzj0C
AQYFK4EEAAoDQgAEUQMFuiWK6enMEZuGr7yoMXxaJ2OF42beufKu/XTDIwNEFjf6
4iaTgdlfinWQ1fcRQOypoyEulQhSjxw0E8Nau6NCMEAwDgYDVR0PAQH/BAQDAgGW
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0RBBYwFIESY2MxNDUxNEBpY2xvdWQuY29t
MAoGCCqGSM49BAMCA0cAMEQCIFc5QiMK73yh3NoU96sEGYwDmLhKvS+ZrchZWyAh
lT10AiACJH/zgPVYzul5zhsOq9vc3vuRSZ+fX7FS7TFDBMuTWA==
-----END CERTIFICATE-----
`

	userKeyPem = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,909ca5b2066d18932a3074058e20f1fd

VSEu1tS4jKptoXO8AByRvRBTGx6NZMCBliwT4DlmsbkJXv6EZQBVqnkxr8DM8mOp
P94NS7z2IYxPjDT/t5wG7KIYts/hIwo6BvM7kzEkMws2cpBlMTkWLTPvmarkl54p
JWI3OZOFCPYPpsgTnKgYpB0Kq/MU7EYgFkBTqXZdYp8=
-----END ECC PRIVATE KEY-----

-----BEGIN ECC PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEmrgTlwGqepeCgGjg+HIryk9NqsG3hLp4
LXMHorL17955PjDRiubxJooDIJGNsqfxfeeq0UFEzRzbc1F60JM0Xw==
-----END ECC PUBLIC KEY-----
`
	userCertPem = `-----BEGIN CERTIFICATE-----
MIIBtjCCAVygAwIBAgIRALcgBnxhpEA0r3XC1OcL4iEwCgYIKoZIzj0EAwIwSjEP
MA0GA1UEBgwG5Lit5Zu9MQ8wDQYDVQQKDAbnu4Tnu4cxFTATBgNVBAsMDOe7hOe7
h+WNleS9jTEPMA0GA1UEAwwG5L2g5aW9MB4XDTIwMDcxNzA1MjcyNloXDTMwMDcx
NTA1MjcyNlowRzEPMA0GA1UEBgwG5Lit5Zu9MRIwEAYDVQQKDAnnsr7mrabpl6gx
DzANBgNVBAsMBuaxn+a5ljEPMA0GA1UEAwwG6ZmI55yfMFYwEAYHKoZIzj0CAQYF
K4EEAAoDQgAEmrgTlwGqepeCgGjg+HIryk9NqsG3hLp4LXMHorL17955PjDRiubx
JooDIJGNsqfxfeeq0UFEzRzbc1F60JM0X6MpMCcwDgYDVR0PAQH/BAQDAgSwMBUG
A1UdEQQOMAyBCmN6QGp3bS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgIaFwCJChgxSM
y7m8b0vNK6tC9ySpq9NifMk2UPqa090CIQDRRllF+O3UGaLwTEBGkyoIl2fBaqdY
wicfuwjfHeYr8A==
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
	prv, pub := kt.GenKey(elliptic.S256(), pwd)
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
	userPrv, userPub := kt.GenKey(elliptic.S256(), pwd)
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

func TestAll(t *testing.T) {
	caKeyPem, pub := kt.GenKey(elliptic.P256(), pwd)
	fmt.Println("==================================================================== ca key")
	fmt.Println(string(caKeyPem))
	fmt.Println(string(pub))
	ioutil.WriteFile("/tmp/ca.key", caKeyPem, 0644)
	ioutil.WriteFile("/tmp/ca.pass", []byte(pwd), 0644)
	fmt.Println("==================================================================== ca cert")

	prv := prvkeyByPem(string(caKeyPem), pwd)
	caCertPem := kt.GenCertForPubkey(prv, nil, prv.Public(), &Subject{
		Country:            "中国",
		OrganizationalUnit: "组织单位",
		Organization:       "组织",
		CommonName:         "你好",
		Email:              "cc14514@icloud.com",
	})
	fmt.Println(string(caCertPem))
	ioutil.WriteFile("/tmp/ca.pem", caCertPem, 0644)

	fmt.Println("==================================================================== user key")
	userPrv, userPub := kt.GenKey(elliptic.P256(), pwd)
	// 输出用户密钥 >>>>>>>>
	fmt.Println(string(userPrv))
	fmt.Println(string(userPub))
	ioutil.WriteFile("/tmp/user.key", userPrv, 0644)
	ioutil.WriteFile("/tmp/user.pass", []byte(pwd), 0644)
	// 输出用户密钥 <<<<<<<<
	// 解析 PEM 公钥 >>>>>>
	fmt.Println("==================================================================== user cert")
	userPubBlk, _ := pem.Decode(userPub)
	ipub, err := x509.ParsePKIXPublicKey(userPubBlk.Bytes)
	if err != nil {
		panic(err)
	}
	upub := ipub.(crypto.PublicKey)
	// 解析 PEM 公钥 <<<<<<

	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 >>>>
	caCertBlk, _ := pem.Decode([]byte(caCertPem))
	caCert, err := x509.ParseCertificate(caCertBlk.Bytes)
	if err != nil {
		panic(err)
	}
	caPrv := prvkeyByPem(string(caKeyPem), pwd)
	userCertPem := kt.GenCertForPubkey(caPrv, caCert, upub, &Subject{
		Country:            "中国",
		OrganizationalUnit: "江湖",
		Organization:       "精武门",
		CommonName:         "helloworld.com",
		Email:              "cz@jwm.com",
	})
	fmt.Println(string(userCertPem))
	ioutil.WriteFile("/tmp/user.pem", userCertPem, 0644)
	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 <<<<

	userCertPemBlk, _ := pem.Decode(userCertPem)

	userCert, err := x509.ParseCertificate(userCertPemBlk.Bytes)
	t.Log(err, userCert.OCSPServer)
}

func TestOcsp(t *testing.T) {
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
	t.Log("user", userCert.SerialNumber, "ca", caCert.SerialNumber, caCert.Subject.String())
	ocspReq, err := ocsp.CreateRequest(userCert, caCert, nil)
	t.Log(err, ocspReq)
	req, _ := ocsp.ParseRequest(ocspReq)

	// IssuerNameHash = Hash(DN) , DN = RawSubject
	// IssuerKeyHash = Hash(Publickey) , Publickey = RawSubjectPublicKeyInfo.PublicKey
	t.Log(req.IssuerNameHash, req.IssuerKeyHash, req.SerialNumber)

	hasher := req.HashAlgorithm.New()
	hasher.Write(caCert.RawSubject)
	h1 := hasher.Sum(nil)

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		t.Error(err)
	}
	hasher.Reset()
	hasher.Write(publicKeyInfo.PublicKey.RightAlign())
	h2 := hasher.Sum(nil)

	t.Log(h1, h2)

}

func TestSignCert(t *testing.T) {
	caKeyPem, err := ioutil.ReadFile("/Users/liangc/certs/ca.key")
	if err != nil {
		panic(err)
	}
	caPrv := prvkeyByPem(string(caKeyPem), pwd)

	fmt.Println("==================================================================== client key")
	userPrv, userPub := kt.GenKey(elliptic.S256(), pwd)
	// 输出用户密钥 >>>>>>>>
	fmt.Println(string(userPrv))
	fmt.Println(string(userPub))
	ioutil.WriteFile("/tmp/client.key", userPrv, 0644)
	ioutil.WriteFile("/tmp/client.pass", []byte(pwd), 0644)
	// 输出用户密钥 <<<<<<<<
	// 解析 PEM 公钥 >>>>>>
	fmt.Println("==================================================================== client cert")
	userPubBlk, _ := pem.Decode(userPub)
	ipub, err := x509.ParsePKIXPublicKey(userPubBlk.Bytes)
	if err != nil {
		panic(err)
	}
	upub := ipub.(crypto.PublicKey)
	// 解析 PEM 公钥 <<<<<<

	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 >>>>
	caCertBlk, _ := pem.Decode([]byte(caCertPem))
	caCert, err := x509.ParseCertificate(caCertBlk.Bytes)
	if err != nil {
		panic(err)
	}
	userCertPem := kt.GenCertForPubkey(caPrv, caCert, upub, &Subject{
		Country:            "中国",
		OrganizationalUnit: "江湖",
		Organization:       "精武门",
		CommonName:         "liangc-client-test",
		Email:              "cz@jwm.com",
	})
	fmt.Println(string(userCertPem))
	ioutil.WriteFile("/tmp/client.pem", userCertPem, 0644)
	// 解析 CA 证书和密钥并对用户 pubkey 签发证书 <<<<

	userCertPemBlk, _ := pem.Decode(userCertPem)

	userCert, err := x509.ParseCertificate(userCertPemBlk.Bytes)
	t.Log(err, userCert.OCSPServer)
}

func TestLoadKey(t *testing.T) {
	userPrv, err := ioutil.ReadFile("/tmp/user.key")
	if err != nil {
		panic(err)
	}
	userPrvBlk, _ := pem.Decode(userPrv)
	userPrvBuf, err := x509.DecryptPEMBlock(userPrvBlk, []byte(pwd))
	if err != nil {
		panic(err)
	}
	uprv, err := x509.ParseECPrivateKey(userPrvBuf)
	if err != nil {
		panic(err)
	}
	fmt.Println(uprv)

}

func TestShow(t *testing.T) {
	data, err := ioutil.ReadFile("/Users/liangc/certs/user.pem")
	if err != nil {
		panic(err)
	}
	blk, _ := pem.Decode(data)
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		panic(err)
	}
	t.Log(crt.SerialNumber)
}
