package desensitivity

// SenString 敏感string类型
type SenString string

func (s SenString) String() string {
	res, _, _ := ShieldField(string(s))
	return res
}
func (s SenString) Value() string {
	return string(s)
}
func (s SenString) MarshalJSON() ([]byte, error) {
	res, _, _ := ShieldField(string(s))
	return []byte(`"` + res + `"`), nil
}

// SenMap 敏感map[string]interface{}类型
type SenMap map[string]interface{}

func (s SenMap) String() string {
	return "[SENSITIVE DATA]"
}
func (s SenMap) Value() map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range s {
		res[k] = v
	}
	return res
}
func (s SenMap) MarshalJSON() ([]byte, error) {
	return []byte(`"[SENSITIVE DATA]"`), nil
}

// SenStringSlice 敏感[]string类型
type SenStringSlice []string

func (s SenStringSlice) String() string {
	return "[SENSITIVE DATA]"
}
func (s SenStringSlice) Value() []string {
	res := []string{}
	for _, v := range s {
		res = append(res, v)
	}
	return res
}
func (s SenStringSlice) MarshalJSON() ([]byte, error) {
	return []byte(`"[SENSITIVE DATA]"`), nil
}
