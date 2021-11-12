# ginny-desensitivity
desensitivity data for ginny.


# Usage

## 脱敏

修改entiry实体字段数据类型:

原类型 | 脱敏类型 | 备注 |
--- | --- | --- |
string | SenString | 
map[string]interface{} | SenMap
[]string | SenStringSlice

示例:

```go
type account struct {
    Id      primitive.ObjectID `json:"-"`
    Name    string             `json:"name"`  
    Phone   SenString          `json:"phone"` // string 替换为 SenString
}

acc := &account{
    Name:   "111111111111111111",
    Phone: "13333333333",
}

```

脱敏打印输出(支持包括zap等常见的logger组件):

```go

fmt.Printf("%v\n", acc) 
log.Printf("%v\n", acc) 
// 打印结果 
// &{ObjectID("000000000000000000000000") 111111111111111111 133****3333} 
// Phone已经被脱敏
```

## 加密

除字段打印脱敏以外，还支持将敏感字段加密。加密后的密文包含明文首尾部分，支持数据库模糊查询

按照上文修改entiry实体字段数据类型：

```go
type account struct {
    Id      primitive.ObjectID `json:"-"`
    Name    string             `json:"name"`  
    Phone   SenString          `json:"phone"` // string 替换为 SenString
}

acc := &account{
    Name:   "111111111111111111",
    Phone: "13333333333",
}

err := EncryptStruct(acc)

fmt.Printf("%#v\n", acc)
// {Id:primitive.ObjectID{xxx}, Name:"111111111111111111", Phone:"133@11@ENC@a150a459e38aa822866183ce2f00bcb4@Z/QfsY+PiDBSQ8Vj926qOA==@3333"}
// Phone已经自动被加密
```

* EncryptString/DecryptString 加解密字符串
* EncryptStruct/DecryptStruct 加密文件
* EncryptFile/DecryptFile 加解密文件, 支持struct、*struct, 并且支持嵌套 []string、[]struct、[]*struct、map[string]interface
* EncryptSlice/DecryptSlice 加解密切片, 支持 []string、[]struct、[]*struct
* EncryptMap/DecryptMap 加解密map, 仅支持 map[string]string 类型值, 其他类型忽略

## 文件加密

项目中经常有存储头像、证件照片等需求场景,对于此类文件需要加密存储,可以使用文件加解密函数


```go
plaintext, err := ioutil.ReadFile("./go.mod")
assert.NoError(t, err)

bt, err := EncryptFile(plaintext)
assert.NoError(t, err)
fmt.Printf("%#v\n", string(bt))

bt, err = DecryptFile(bt)
assert.NoError(t, err)
fmt.Printf("%#v\n", string(bt))
```

# 问题

- 1、脱敏的字段在参数传递时，并不会影响值(不会脱敏)，但是在涉及到字符串拼接等场景可能会出现问题，例如
  ```go
    str := fmt.Sprintf("张三的手机: %s", acc.Phone)
    // str = 张三的手机: 133****3333
  ```
  修改为 .Value() 取值
  ```go
    str := fmt.Sprintf("张三的手机: %s", acc.Phone.Value())
    // str = 张三的手机: 13333333333
  ```
- 2、使用 %#v 打印的时候，脱敏不生效，因为底层会循环k，v，并没有调用 String()函数，导致脱敏失效，例如
  ```go
    fmt.Printf("%#v\n", acc)
  ```
  修改为 %v 或者 %+v
  ```go
    fmt.Printf("%+v\n", acc)
  ```

- 3、gin、echo等框架在handle输出的时候，往往会使用 c.JSON , 导致输出的内容被脱敏，与预期不符, 例如:

  ```go
    type account struct {
        Id      primitive.ObjectID `json:"-"`
        Name    string             `json:"name"`
        Phone   Sensitivity        `json:"phone"`
    }

    // gin handler函数
    func Handler(c *gin.Context) {
        ...
        acc := &account{
        Name:   "111111111111111111",
        Phone: "13333333333",
        }
        c.JSON(acc)    // api输出被脱敏
    }
  ```
  结构体增加自定义 MarshalJSON
  ```go
    func (u *account) MarshalJSON() ([]byte, error) {
        return json.Marshal(&struct {
            Id      primitive.ObjectID `bson:"_id"`
            Name    string             `bson:"name"`
            Phone   string             `bson:"phone"`
        }{
            Id:      u.Id,
            Name:    u.Name,
            Phone:   u.Phone.Value(),
        })
    }
    // gin handler函数
    func Handler(c *gin.Context) {
        ...
        acc := &account{
        Name:   "111111111111111111",
        Phone: "13333333333",
        }
        bt, _ := acc.MarshalJSON() // 调用自定义Marshal
        c.JSON(string(bt))  // 输出json字符串
    }
  ```
- 4、敏感字段加密，struct、slice、map有类型限制吗？
  

    类型 | 加密支持类型 | 备注 |
    --- | --- | --- |
    struct | struct 或 *struct | 支持嵌套 []string、[]struct、[]*struct、map[string]interface
    map | map[string]interface{} | 仅支持值类型为 map[string]string 
    slice | 支持 []string、[]struct、[]*struct | []struct、[]*struct 中不建议再嵌套,效率很低