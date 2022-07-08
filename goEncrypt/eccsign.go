package goEncrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"runtime"
)

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile)
}

// EccSign ECC签名
func EccSign(msg []byte, Key []byte) ([]byte, []byte, error) {
	block, _ := pem.Decode(Key)

	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err != nil {
		return nil, nil, err
	}

	// 结果
	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}

	// 签名
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}

	// 返回结果和签名
	return rText, sText, nil
}

func EccVerifySign(msg []byte, Key []byte, rText, sText []byte) bool {
	block, _ := pem.Decode(Key)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}
