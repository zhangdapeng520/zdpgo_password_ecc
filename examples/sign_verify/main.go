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
@Description: ecc加密解密字符串 不使用base64编码
*/

func main() {
	e, _ := zdpgo_password_ecc.New()

	s := "abc"
	data := []byte(s)
	fmt.Println(s)

	// 数据签名
	signData, err := e.Sign(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(signData))

	// 校验数据
	flag := e.Verify(data, signData)
	if !flag {
		panic("校验结果错误")
	}
	fmt.Println(flag)
}
