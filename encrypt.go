package desensitivity

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/goriller/ginny-encrypt/aes"
)

var encryptFileLen = 100

// AesEncrypt
func AesEncrypt(iv, data string) (string, error) {
	cipher := aes.NewCBC()
	bt, err := cipher.Encrypt([]byte(iv), []byte(data))
	if err != nil {
		return "", err
	}
	str := base64.StdEncoding.EncodeToString(bt)
	return str, nil
}

// AesDecrypt
func AesDecrypt(iv, data string) (string, error) {
	cipher := aes.NewCBC()
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	bt, err := cipher.Decrypt([]byte(iv), b)
	if err != nil {
		return "", err
	}
	return string(bt), nil
}

// encryptString
func encryptString(field string, opt *Options) (string, error) {
	return EncryptString(field, opt)
}

// decryptString
func decryptString(field string, opt *Options) (string, error) {
	return DecryptString(field, opt)
}

// isEncryptText
func isEncryptText(text string, opt ...*Options) bool {
	option := getDefaultOption(opt...)
	return strings.Count(text, option.step) == 5 &&
		strings.Contains(text, fmt.Sprintf("%s%s%s", option.step, option.tag, option.step))
}

// EncryptString
// 输入明文字段,自动加密
// 如果修改了加密配置，需要传入配置
func EncryptString(field string, opt ...*Options) (string, error) {
	// options
	option := getDefaultOption(opt...)
	// 判断是否密文
	if isEncryptText(field, opt...) {
		return field, nil
	}

	key1 := splitString(field)
	hashKey1 := string([]rune(sha256Crypt(key1))[:32])
	encryptKey3 := md5Crypt(hashKey1 + option.encryptKey)

	encryptText, err := AesEncrypt(encryptKey3, field)
	if err != nil {
		return "", err
	}
	lens := utf8.RuneCountInString(field)
	_, prefix, subfix := ShieldField(field)
	return fmt.Sprintf("%s%s%d%s%s%s%s%s%s%s%s",
		prefix, option.step, lens, option.step, option.tag, option.step,
		hashKey1, option.step, encryptText, option.step, subfix), nil
}

// DecryptString
// 输入密文字段,自动解密
// 如果修改了加密配置，需要传入配置
func DecryptString(text string, opt ...*Options) (string, error) {
	// options
	option := getDefaultOption(opt...)
	// 判断是否密文
	if !isEncryptText(text, opt...) {
		return text, nil
	}
	strArr := strings.Split(text, option.step)

	hashKey1 := strArr[3]
	encryptText := strArr[4]
	if hashKey1 == "" || encryptText == "" {
		return "", fmt.Errorf("not a correct encrypted string")
	}
	encryptKey3 := md5Crypt(hashKey1 + option.encryptKey)
	dText, err := AesDecrypt(encryptKey3, encryptText)
	if err != nil {
		return "", err
	}
	return dText, nil
}

// EncryptFile
// 加密存储文件,只加密头部encryptFileLen长度的内容，再拼接加密+非加密内容存储
func EncryptFile(plaintext []byte, opt ...*Options) ([]byte, error) {
	var (
		toEncrData   []byte
		toAppendData []byte
	)
	if len(plaintext) <= encryptFileLen {
		toEncrData = plaintext
	} else {
		toEncrData = plaintext[:encryptFileLen]
		toAppendData = plaintext[encryptFileLen:]
	}

	cipher := aes.NewCFB()
	option := getDefaultOption(opt...)
	key := md5Crypt(option.encryptKey)
	encrData, err := cipher.Encrypt([]byte(key), toEncrData)
	if err != nil {
		return nil, err
	}
	dst := append(encrData, toAppendData...)
	return dst, nil
}

// DecryptFile
// 加密文件解密
func DecryptFile(fileData []byte, opt ...*Options) ([]byte, error) {
	var (
		encryptedData   []byte
		unEncryptedData []byte
	)
	if len(fileData) <= encryptFileLen+16 {
		encryptedData = fileData
	} else {
		encryptedData = fileData[:encryptFileLen+16]
		unEncryptedData = fileData[encryptFileLen+16:]
	}

	cipher := aes.NewCFB()
	option := getDefaultOption(opt...)
	key := md5Crypt(option.encryptKey)
	encrData, err := cipher.Decrypt([]byte(key), encryptedData)
	if err != nil {
		return nil, err
	}
	dst := append(encrData, unEncryptedData...)
	return dst, nil
}

// EncryptStruct
// 支持struct、*struct, 并且支持嵌套 []string、[]struct、[]*struct、map[string]interface
func EncryptStruct(p interface{}, opt ...*Options) error {
	v, err := getStructValue(p)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setEncryptValue(v, option)
}

// DecryptStruct
// 支持struct、*struct, 并且支持嵌套 []string、[]struct、[]*struct、map[string]interface
func DecryptStruct(p interface{}, opt ...*Options) error {
	v, err := getStructValue(p)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setDecryptValue(v, option)
}

// EncryptSlice
// 支持 []string、[]struct、[]*struct
func EncryptSlice(s interface{}, opt ...*Options) error {
	v, err := getSliceValue(s)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setEncryptSlice(v, option)
}

// DecryptSlice
// 支持 []string、[]struct、[]*struct
func DecryptSlice(s interface{}, opt ...*Options) error {
	v, err := getSliceValue(s)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setDecryptSlice(v, option)
}

// EncryptMap
// 仅支持 map[string]string 类型值, 其他类型忽略
func EncryptMap(mp map[string]interface{}, opt ...*Options) error {
	v, err := getMapValue(mp)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setEncryptMap(v, option)
}

// DecryptMap
// 仅支持 map[string]string 类型值, 其他类型忽略
func DecryptMap(mp map[string]interface{}, opt ...*Options) error {
	v, err := getMapValue(mp)
	if err != nil {
		return err
	}
	option := getDefaultOption(opt...)
	return setDecryptMap(v, option)
}

// getStructValue
func getStructValue(s interface{}) (v reflect.Value, err error) {
	t := reflect.TypeOf(s)
	switch t.Kind() {
	case reflect.Ptr:
		v = reflect.ValueOf(s).Elem()
	case reflect.Struct:
		v = reflect.ValueOf(s)
	default:
		err = fmt.Errorf("Data type error")
	}
	return
}

// getSliceValue
func getSliceValue(s interface{}) (v reflect.Value, err error) {
	t := reflect.TypeOf(s)
	switch t.Kind() {
	case reflect.Ptr:
		v = reflect.ValueOf(s).Elem()
	case reflect.Slice:
		v = reflect.ValueOf(s)
	default:
		err = fmt.Errorf("Data type error")
	}
	return
}

// getMapValue
func getMapValue(s interface{}) (v reflect.Value, err error) {
	t := reflect.TypeOf(s)
	switch t.Kind() {
	case reflect.Ptr:
		v = reflect.ValueOf(s).Elem()
	case reflect.Map:
		v = reflect.ValueOf(s)
	default:
		err = fmt.Errorf("Data type error")
	}
	return
}

// setEncryptValue
func setEncryptValue(v reflect.Value, option *Options) error {
	// 循环属性
	for i := 0; i < v.NumField(); i++ {
		// fn := v.Type().Field(i).Name
		value := v.Field(i)
		vn := value.String()
		tn := value.Type().Name()
		// 嵌套Struct
		if value.Kind() == reflect.Struct {
			if err := setEncryptValue(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}
		// 嵌套SenStringSlice
		if tn == "SenStringSlice" {
			if err := setEncryptSlice(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}
		// 嵌套SenMap
		if tn == "SenMap" {
			if err := setEncryptMap(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}

		// 值无效的情况跳过
		if tn != "SenString" || !value.IsValid() || vn == "" || isEncryptText(vn, option) {
			continue
		}
		str, err := option.encryptFn(vn, option)
		if err != nil {
			return err
		}
		// fmt.Printf("%v: %v; %s\n", fn, vn, str)
		value.Set(reflect.ValueOf(str).Convert(value.Type()))
	}
	return nil
}

// setDecryptValue
func setDecryptValue(v reflect.Value, option *Options) error {
	// 循环属性
	for i := 0; i < v.NumField(); i++ {
		// fn := v.Type().Field(i).Name
		value := v.Field(i)
		vn := value.String()
		tn := value.Type().Name()
		// 嵌套Struct
		if value.Kind() == reflect.Struct {
			if err := setDecryptValue(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}
		// 嵌套SenStringSlice
		if tn == "SenStringSlice" {
			if err := setDecryptSlice(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}
		// 嵌套SenMap
		if tn == "SenMap" {
			if err := setDecryptMap(reflect.Indirect(v.Field(i)), option); err != nil {
				return err
			}
			continue
		}

		// 值无效的情况跳过
		if tn != "SenString" || !value.IsValid() || vn == "" || !isEncryptText(vn, option) {
			continue
		}
		str, err := option.decryptFn(vn, option)
		if err != nil {
			return err
		}
		// fmt.Printf("%v: %v; %s\n", fn, vn, str)
		// v.FieldByName(fn).Set(reflect.ValueOf(str))
		value.Set(reflect.ValueOf(str).Convert(value.Type()))
	}
	return nil
}

// setEncryptSlice
func setEncryptSlice(v reflect.Value, opt *Options) error {
	var z reflect.Value
	for i := 0; i < v.Len(); i++ {
		vn := v.Index(i)
		k := vn.Kind()
		if k == reflect.String { // []string类型
			if err := setEncryptSliceValue(v, vn, opt); err != nil {
				return err
			}
			continue
		} else if k == reflect.Struct {
			z = vn
		} else if k == reflect.Ptr {
			z = reflect.Indirect(vn)
		} else {
			continue
			//其他类型暂时不处理, 使用时候需要注意
			// Bool、Int、Int8、Int16、Int32、Int64、Uint、Uint8、Uint16
			// Uint32、Uint64、Uintptr、Float32、Float64、Complex64
			// Complex128、Array、Chan、Func、Interface、UnsafePointer
		}
		// fmt.Printf("%v: %v; \n", i, z.NumField())
		if err := setEncryptValue(z, opt); err != nil {
			return err
		}
	}
	return nil
}

// setEncryptSliceValue
func setEncryptSliceValue(v, vn reflect.Value, opt *Options) error {
	if vn.IsValid() {
		svn := vn.String()
		str, err := opt.encryptFn(svn, opt)
		if err != nil {
			return err
		}
		vn.Set(reflect.ValueOf(str).Convert(vn.Type()))
	}
	return nil
}

// setDecryptSlice
func setDecryptSlice(v reflect.Value, opt *Options) error {
	var z reflect.Value
	for i := 0; i < v.Len(); i++ {
		vn := v.Index(i)
		k := vn.Kind()
		if k == reflect.String { // []string类型
			if err := setDecryptSliceValue(v, vn, opt); err != nil {
				return err
			}
			continue
		} else if k == reflect.Struct {
			z = vn
		} else if k == reflect.Ptr {
			z = reflect.Indirect(vn)
		} else {
			continue
			//其他类型暂时不处理, 使用时候需要注意
			// Bool、Int、Int8、Int16、Int32、Int64、Uint、Uint8、Uint16
			// Uint32、Uint64、Uintptr、Float32、Float64、Complex64
			// Complex128、Array、Chan、Func、Interface、UnsafePointer
		}
		// fmt.Printf("%v: %v; \n", i, z.NumField())
		if err := setDecryptValue(z, opt); err != nil {
			return err
		}
	}
	return nil
}

// setDecryptSliceValue
func setDecryptSliceValue(v, vn reflect.Value, opt *Options) error {
	if vn.IsValid() {
		svn := vn.String()
		str, err := opt.decryptFn(svn, opt)
		if err != nil {
			return err
		}
		vn.Set(reflect.ValueOf(str).Convert(vn.Type()))
	}
	return nil
}

// setEncryptMap
func setEncryptMap(val reflect.Value, option *Options) error {
	keys := val.MapKeys()
	for _, k := range keys {
		value := val.MapIndex(k)
		vn := value.Elem()
		// fmt.Printf("%v: %v: %v; \n", k, vn.Kind(), vn.Type().Name())
		if vn.Type().Name() == "string" {
			if err := setEncryptMapValue(k, val, value, option); err != nil {
				return err
			}
			continue
		}
	}
	return nil
}

// setEncryptMapValue
func setEncryptMapValue(key, v, sv reflect.Value, option *Options) error {
	vn := fmt.Sprintf("%#v", sv)
	if strings.HasPrefix(vn, `"`) {
		rn := []rune(vn)
		vn = string(rn[1 : len(rn)-1])
	}

	// 值无效的情况跳过
	if !sv.IsValid() || vn == "" || isEncryptText(vn, option) {
		return nil
	}
	str, err := option.encryptFn(vn, option)
	if err != nil {
		return err
	}
	v.SetMapIndex(key, reflect.ValueOf(str).Convert(sv.Type()))
	return nil
}

// setDecryptMap
func setDecryptMap(val reflect.Value, option *Options) error {
	keys := val.MapKeys()
	for _, k := range keys {
		value := val.MapIndex(k)
		vn := value.Elem()
		// fmt.Printf("%v: %v: %v; \n", k, vn.Kind(), vn.Type().Name())
		if vn.Type().Name() == "string" {
			if err := setDecryptMapValue(k, val, value, option); err != nil {
				return err
			}
			continue
		}
	}
	return nil
}

// setDecryptMapValue
func setDecryptMapValue(key, v, sv reflect.Value, option *Options) error {
	vn := fmt.Sprintf("%#v", sv)
	if strings.HasPrefix(vn, `"`) {
		rn := []rune(vn)
		vn = string(rn[1 : len(rn)-1])
	}
	// 值无效的情况跳过
	if !sv.IsValid() || vn == "" || !isEncryptText(vn, option) {
		return nil
	}
	str, err := option.decryptFn(vn, option)
	if err != nil {
		return err
	}
	v.SetMapIndex(key, reflect.ValueOf(str).Convert(sv.Type()))
	return nil
}

// chineseToUnicode
// 中文转 unicode
func chineseToUnicode(str string) string {
	textQuoted := strconv.QuoteToASCII(str)
	textUnquoted := textQuoted[1 : len(textQuoted)-1]
	return textUnquoted
}

// hasChinese
// 判断字符串是否包含中文
func hasChinese(str string) bool {
	var count int
	for _, v := range str {
		if unicode.Is(unicode.Han, v) {
			count++
			break
		}
	}
	return count > 0
}

// Md5Crypt
func md5Crypt(str string, salt ...interface{}) string {
	if l := len(salt); l > 0 {
		slice := make([]string, l+1)
		str = fmt.Sprintf(str+strings.Join(slice, "%v"), salt...)
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(str)))
}

// sha256Crypt
func sha256Crypt(str string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// splitString
// 截取字符串,不足8位0补位
func splitString(field string) string {
	str := field
	if hasChinese(field) {
		str = chineseToUnicode(field)
	}
	if l := len(str); l < 8 {
		for i := 0; i < (8 - l); i++ {
			str += "0"
		}
	}
	return string([]rune(str)[:8])
}
