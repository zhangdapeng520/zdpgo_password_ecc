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
	fmt.Println("加密前的数据：", s)
	data := []byte(s)

	// 加密数据
	encryptData, err := e.Encrypt(data)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密后的数据：", string(encryptData))

	// 解密数据
	decrypt, err := e.Decrypt(encryptData)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密后的数据：", string(decrypt))

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}
