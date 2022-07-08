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

	s := "abc"
	data := []byte(s)

	// 获取私钥和公钥
	privateKey, publicKey, err := e.GetKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("获取到的私钥：", string(privateKey))
	fmt.Println("获取到的公钥：", string(publicKey))

	// 加密数据
	encryptData, err := e.EncryptByPublicKey(data, publicKey)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypt, err := e.DecryptByPrivateKey(encryptData, privateKey)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
	fmt.Println("加密前的数据：", s)
	fmt.Println("解密后的数据：", string(decrypt))

	// 指定key
	e, _ = zdpgo_password_ecc.NewWithConfig(&zdpgo_password_ecc.Config{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})

	// 加密数据
	encryptData, err = e.EncryptByPublicKey(data, publicKey)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypt, err = e.DecryptByPrivateKey(encryptData, privateKey)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}
