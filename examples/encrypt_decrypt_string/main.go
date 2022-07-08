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
	fmt.Println(s)

	// 加密数据
	encryptString, err := e.EncryptString(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(encryptString)

	// 解密数据
	decryptString, err := e.DecryptString(encryptString)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != decryptString {
		panic("加密前的数据和解密后的数据不一致")
	}
	fmt.Println(decryptString)
}
