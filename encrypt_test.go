package desensitivity

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testStruct struct {
	Phone   SenString
	Name    string
	Pet     SenStringSlice
	Profile SenMap
}

func TestEncryptStruct(t *testing.T) {
	tu := &testStruct{
		Phone: "13300000000",
		Name:  "张三",
		Pet:   SenStringSlice{"cat", "dog"},
		Profile: SenMap{
			"age":   18,
			"class": "a",
		},
	}

	err := EncryptStruct(tu)
	assert.NoError(t, err)

	assert.Equal(t, tu.Phone.Value(), "133@11@ENC@92f79f0118437ee3c9810158fca9a082@ZBe+NDOAnCR8EMhYli/7Uw==@0000")
	fmt.Printf("%#v\n", tu)
}

func TestDecryptStruct(t *testing.T) {
	tu := &testStruct{
		Phone: "133@11@ENC@92f79f0118437ee3c9810158fca9a082@ZBe+NDOAnCR8EMhYli/7Uw==@0000",
		Name:  "张三",
		Pet: SenStringSlice{"c@3@ENC@c1212ce669b9a65612a001dd18e689ff@8C55Y0JiluY8Qiu4XsHtyg==@t",
			"d@3@ENC@8c868bb61fb4bf7dc04c7787331a2b54@1NK5Og32vIkPgT6okRrHVQ==@g"},
		Profile: SenMap{
			"age":   18,
			"class": "*@1@ENC@92053360555ae3b1b6a514c591ed1268@8y7AyxdN+7X4eBPuV2rioA==@",
		},
	}
	err := DecryptStruct(tu)
	assert.NoError(t, err)

	assert.Equal(t, tu.Phone.Value(), "13300000000")
	fmt.Printf("%#v\n", tu)
}

func TestEncryptSlice(t *testing.T) {
	tu := []*testStruct{
		{
			Phone: "13300000000",
			Name:  "张三",
			Pet:   SenStringSlice{"cat", "dog"},
			Profile: SenMap{
				"age":   18,
				"class": "a",
			},
		},
	}
	err := EncryptSlice(tu)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu[0])
	tu1 := []testStruct{
		{
			Phone: "13300000000",
			Name:  "张三",
			Pet:   SenStringSlice{"cat", "dog"},
			Profile: SenMap{
				"age":   18,
				"class": "a",
			},
		},
	}
	err = EncryptSlice(tu1)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu1)
}

func TestDecryptSlice(t *testing.T) {
	tu := []*testStruct{
		{
			Phone: "133@11@ENC@92f79f0118437ee3c9810158fca9a082@ZBe+NDOAnCR8EMhYli/7Uw==@0000",
			Name:  "张三",
			Pet: SenStringSlice{"c@3@ENC@c1212ce669b9a65612a001dd18e689ff@8C55Y0JiluY8Qiu4XsHtyg==@t",
				"d@3@ENC@8c868bb61fb4bf7dc04c7787331a2b54@1NK5Og32vIkPgT6okRrHVQ==@g"},
			Profile: SenMap{
				"age":   18,
				"class": "*@1@ENC@92053360555ae3b1b6a514c591ed1268@8y7AyxdN+7X4eBPuV2rioA==@",
			},
		},
	}
	err := DecryptSlice(tu)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu[0])
	tu1 := []testStruct{
		{
			Phone: "133@11@ENC@92f79f0118437ee3c9810158fca9a082@ZBe+NDOAnCR8EMhYli/7Uw==@0000",
			Name:  "张三",
			Pet: SenStringSlice{"c@3@ENC@c1212ce669b9a65612a001dd18e689ff@8C55Y0JiluY8Qiu4XsHtyg==@t",
				"d@3@ENC@8c868bb61fb4bf7dc04c7787331a2b54@1NK5Og32vIkPgT6okRrHVQ==@g"},
			Profile: SenMap{
				"age":   18,
				"class": "*@1@ENC@92053360555ae3b1b6a514c591ed1268@8y7AyxdN+7X4eBPuV2rioA==@",
			},
		},
	}
	err = DecryptSlice(tu1)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu1)
}

func TestEncryptMap(t *testing.T) {
	tu := SenMap{
		"Phone": "13300000000",
		"Name":  "张三",
		"Pet":   "cat",
		"age":   18,
	}
	err := EncryptMap(tu)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu["Struct"])
	fmt.Printf("%#v\n", tu)
}
func TestDecryptMap(t *testing.T) {
	tu := SenMap{
		"Phone": "133@11@ENC@92f79f0118437ee3c9810158fca9a082@ZBe+NDOAnCR8EMhYli/7Uw==@0000",
		"Name":  "张@2@ENC@6e9aa60eebeccff94ddd52cfe9124614@W70R9aPCxRw1BYb/PWmS+g==@*",
		"Pet":   "c@3@ENC@c1212ce669b9a65612a001dd18e689ff@8C55Y0JiluY8Qiu4XsHtyg==@t",
		"age":   18,
	}
	err := DecryptMap(tu)
	assert.NoError(t, err)
	fmt.Printf("%#v\n", tu["Struct"])
	fmt.Printf("%#v\n", tu)
}
