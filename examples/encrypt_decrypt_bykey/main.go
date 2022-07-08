package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password_ecc"
)

/*
@Time : 2022/7/8 11:12
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description: ecc加密解密
*/

func main() {
	e, _ := zdpgo_password_ecc.New()

	s := "{\"age\":22}"
	fmt.Println("加密前的数据：", s)
	data := []byte(s)

	// 私钥
	privateKey := `-----BEGIN  ZDPGO_PASSWORD ECC PRIVATE KEY -----
MHcCAQEEIKyfOnD7NdXudekftRtH2mBuOPf/UTzJ1Ulo2Hiu22XvoAoGCCqGSM49
AwEHoUQDQgAEXClGdjDvOFSHJzs2LtSfGcVzP58cc9ybrYOo7t6bs818HMybbahM
Qylb+qB4aTtHV0JPqZAr8MChRmvze7nNFw==
-----END  ZDPGO_PASSWORD ECC PRIVATE KEY -----
`
	// 公钥
	publicKey := `-----BEGIN  ZDPGO_PASSWORD ECC PUBLIC KEY -----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXClGdjDvOFSHJzs2LtSfGcVzP58c
c9ybrYOo7t6bs818HMybbahMQylb+qB4aTtHV0JPqZAr8MChRmvze7nNFw==
-----END  ZDPGO_PASSWORD ECC PUBLIC KEY -----
`

	// 加密数据
	encryptData, err := e.EncryptByPublicKey(data, []byte(publicKey))
	if err != nil {
		panic(err)
	}
	fmt.Println("使用公钥加密后的数据：", string(encryptData))

	// 解密数据
	decrypt, err := e.DecryptByPrivateKey(encryptData, []byte(privateKey))
	if err != nil {
		panic(err)
	}
	fmt.Println("使用私钥解密后的数据：", string(decrypt))

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}
