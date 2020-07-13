package example

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"math/big"
	"time"
)

const (
	TITLE_PUB = "ECC PUBLIC KEY"
	TITLE_KEY = "ECC PRIVATE KEY"
	TITLE_CSR = "CERTIFICATE REQUEST"
	TITLE_CRT = "CERTIFICATE"
)

type Subject struct {
	Country,
	OrganizationalUnit,
	Organization,
	CommonName, Email string
}

func (subject *Subject) tox() pkix.Name {
	if subject == nil {
		return pkix.Name{}
	}
	return pkix.Name{
		Country:            []string{subject.Country},            // 国家地区
		OrganizationalUnit: []string{subject.OrganizationalUnit}, // 组织单位
		Organization:       []string{subject.Organization},       // 组织
		CommonName:         subject.CommonName,                   // IDB58 编码的 ECS256 Pubkey
	}
}

type ECCKeytool struct {
	pubTitle, keyTitle, csrTitle, certTitle string
	agl                                     x509.PEMCipher
	caKeyUsage, userKeyUsage                x509.KeyUsage
}

func NewKeytool() *ECCKeytool {
	return &ECCKeytool{
		pubTitle:  TITLE_PUB,
		keyTitle:  TITLE_KEY,
		csrTitle:  TITLE_CSR,
		certTitle: TITLE_CRT,
		agl:       x509.PEMCipherAES128,
		caKeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageDigitalSignature, // 证书签名，撤销签名，数据加密，数字签名
		userKeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
	}
}

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

func (self *ECCKeytool) exportRawPubkey(pubkey crypto.PublicKey) []byte {
	pubBuf, _ := x509.MarshalPKIXPublicKey(pubkey)
	b := &pem.Block{}
	b.Headers = make(map[string]string)
	b.Type = self.pubTitle
	b.Bytes = pubBuf
	buf := new(bytes.Buffer)
	pem.Encode(buf, b)
	return buf.Bytes()
}

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

	if prvkey.Public() == userPubkey {
		certTemplate.IsCA = true
		certTemplate.BasicConstraintsValid = true
		certTemplate.KeyUsage = self.caKeyUsage
	} else {
		certTemplate.IsCA = false
		certTemplate.KeyUsage = self.userKeyUsage
	}
	if caCert == nil {
		caCert = certTemplate
	}
	fmt.Println("---------------------------------CA---------------------------------", certTemplate.IsCA, caCert.IsCA)
	certBuf, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, userPubkey, prvkey)
	if err != nil {
		panic(err)
	}
	certBlk := &pem.Block{Type: self.certTitle, Headers: make(map[string]string), Bytes: certBuf}
	out := new(bytes.Buffer)
	err = pem.Encode(out, certBlk)
	if err != nil {
		panic(err)
	}
	return out.Bytes()
}
