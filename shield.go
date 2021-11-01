package desensitivity

import (
	"fmt"
	"strings"
)

// ShieldField
// 明文转换为脱敏串
func ShieldField(str string) (res string, start string, end string) {
	l := len([]rune(str))
	s := []rune(str)
	if l <= 1 {
		start = "*"
		end = ""
		res = "*"
	} else if l == 2 {
		start = string(s[:1])
		end = "*"
		res = fmt.Sprintf("%s%s", start, end)
	} else {
		num := l / 3
		mo := l % 3
		startNum := num
		if mo > 0 {
			num = num + 1
		}
		if startNum > 4 {
			num = num + (startNum - 4)
			startNum = 4
		}
		endNum := l - num - startNum
		if endNum > 4 {
			num = num + (endNum - 4)
			// endNum = 4
		}
		// fmt.Printf("%v, %v, %v\n", num, startNum, endNum)
		start = string(s[:startNum])
		end = string(s[num+startNum:])
		res = fmt.Sprintf("%s%s%s", start, strings.Repeat("*", num), end)
	}
	return
}
