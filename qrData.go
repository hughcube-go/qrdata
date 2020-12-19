package qrdata

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hughcube-go/utils/mshash"
	"github.com/hughcube-go/utils/msslice"
	"io"
	"math/rand"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const UserKeyFieldName = "UserKey"
const SignatureFieldName = "Signature"

const DefaultType = "png"
const DefaultSize = 200

type QrData struct {
	UserKey    string `json:"a"`
	UserSecret string `json:"-"`
	Signature  string `json:"c"`
	CreatedAt  int64  `json:"d"`
	Nonce      string `json:"e"`
	Data       string `json:"f"`
	Level      int    `json:"g"`
	Logo       string `json:"h"`
	LogoSize   int    `json:"i"`
	Type       string `form:"j"`
	Size       int    `json:"k"`
}

func NewQrData(userKey string, userSecret string) *QrData {
	data := &QrData{}

	data.SetUserKey(userKey).
		SetUserSecret(userSecret).
		RandomNonce().
		SetCreatedAt(time.Now().UnixNano()).
		SetLevel(2).
		SetType("png").
		SetSize(400)

	return data
}

//
func (d *QrData) SetUserKey(userKey string) *QrData {
	d.UserKey = userKey
	return d
}
func (d *QrData) GetUserKey() string {
	return d.UserKey
}

//
func (d *QrData) SetUserSecret(userSecret string) *QrData {
	d.UserSecret = userSecret
	return d
}
func (d *QrData) GetUserSecret() string {
	return d.UserKey
}

//
func (d *QrData) SetSignature(signature string) *QrData {
	d.Signature = signature
	return d
}

func (d *QrData) GetSignature() string {
	return d.Signature
}

//
func (d *QrData) SetCreatedAt(createdAt int64) *QrData {
	d.CreatedAt = createdAt
	return d
}

func (d *QrData) GetCreatedAt() int64 {
	return d.CreatedAt
}

//
func (d *QrData) RandomNonce() *QrData {
	d.Nonce = fmt.Sprintf("%05v", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(89999)+10000)
	return d
}

func (d *QrData) SetNonce(nonce string) *QrData {
	d.Nonce = nonce
	return d
}

func (d *QrData) GetNonce() string {
	return d.Nonce
}

//
func (d *QrData) SetData(data string) *QrData {
	d.Data = data
	return d
}

func (d *QrData) GetData() string {
	return d.Data
}

//
func (d *QrData) SetLevel(level int) *QrData {
	d.Level = level
	return d
}

func (d *QrData) GetLevel() int {
	return d.Level
}

//
func (d *QrData) SetLogo(logo string) *QrData {
	if _, err := url.Parse(logo); err != nil && 0 < len(logo) {
		println("The logo must be a URL")
	}

	d.Logo = logo
	return d
}

func (d *QrData) GetLogo() string {
	return d.Logo
}

//
func (d *QrData) SetType(t string) *QrData {
	d.Type = t
	return d
}

func (d *QrData) GetType() string {
	if "" == d.Type {
		return DefaultType
	}

	return d.Type
}

//
func (d *QrData) SetSize(size int) *QrData {
	d.Size = size
	return d
}

func (d *QrData) GetSize() int {
	if 0 == d.Size {
		return DefaultSize
	}

	return d.Size
}

//
func (d *QrData) SetLogoSize(size int) *QrData {
	d.LogoSize = size
	return d
}

func (d *QrData) GetLogoSize() int {
	if 0 == d.LogoSize {
		return d.GetSize() / 5
	}

	return d.LogoSize
}

func (d *QrData) MakeSignature() string {
	items := map[string]string{}

	typ := reflect.TypeOf(*d)
	val := reflect.ValueOf(*d)
	for i := 0; i < val.NumField(); i++ {
		key := typ.Field(i)
		value := val.Field(i)

		if value.Kind() == reflect.String {
			items[key.Name] = value.String()
		} else if value.Kind() == reflect.Int || value.Kind() == reflect.Int64 {
			items[key.Name] = strconv.FormatInt(value.Int(), 10)
		} else {
			panic("Unsupported types")
		}
	}

	keys := []string{}
	for key, value := range items {
		if msslice.In(key, UserKeyFieldName, SignatureFieldName) {
			continue
		}

		if value == "" || value == "0" {
			continue
		}

		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := []string{}
	for _, key := range keys {
		values = append(values, items[key])
	}

	return mshash.MD5(strings.Join(values, ","))
}

func (d *QrData) Encode() (string, error) {
	d.SetSignature(d.MakeSignature())

	// 系列化成json
	jsonByte, err := json.Marshal(d)
	if nil != err {
		return "", err
	}

	var zipBuffer bytes.Buffer
	w, err := zlib.NewWriterLevel(&zipBuffer, zlib.BestCompression)
	if err != nil {
		return "", err
	}

	if _, err := w.Write(jsonByte); err != nil {
		return "", err
	}

	if err = w.Close(); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(zipBuffer.Bytes()), nil
}

func Decode(data string) (*QrData, error) {
	// 转换到压缩前
	dataByte, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	// 解压缩
	var dataBuffer bytes.Buffer
	reader, err := zlib.NewReader(bytes.NewReader(dataByte))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if _, err = io.Copy(&dataBuffer, reader); err != nil {
		return nil, err
	}

	// 尝试转换为结构体
	qrData := &QrData{}
	if err = json.Unmarshal(dataBuffer.Bytes(), qrData); err != nil {
		return nil, err
	}

	return qrData, nil
}
