package qrdata

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_QrData_MakeSignature(t *testing.T) {
	data := NewQrData("test", "test").
		SetCreatedAt(1608357849702815000).
		SetNonce("100000").
		SetData("data").
		SetLevel(1).
		SetLogo("http://example.com").
		SetType("png").
		SetSize(100)

	a := assert.New(t)
	a.Equal(data.MakeSignature(), "9e97f64f33ea178f30fbb2ec8ff1cbc4")
}

func Test_QrData_Encode(t *testing.T) {
	a := assert.New(t)

	data := NewQrData("test", "test").
		SetCreatedAt(1608357849702815000).
		SetNonce("100000").
		SetData("data").
		SetLevel(1).
		SetLogo("https://img.caibeitv.com/20201210154656467251094678.jpg").
		SetType("png").
		SetSize(100)

	urlData, err := data.Encode()
	a.Nil(err)

	qrData, err := Decode(urlData)
	a.Nil(err)

	a.Equal(data.SetUserSecret(""), qrData)
}
