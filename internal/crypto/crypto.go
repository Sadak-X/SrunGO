// 提供加密工具

package crypto

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

var (
	customBase64CharList   = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	standardBase64CharList = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

func MD5Hex(password, token string) string {
	sum := md5.Sum([]byte(token + password))
	return hex.EncodeToString(sum[:])
}

func SHA1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// 将字符串切分为元素为 uint32 格式的数组
func SliceString(inputString string, includeLength bool) []uint32 {
	var slicedArray []uint32
	for i := 0; i < len(inputString); i += 4 {
		var val uint32 = 0
		for j := 0; j < 4; j++ {
			if i+j < len(inputString) {
				val |= uint32(inputString[i+j]) << (uint(j) * 8)
			}
		}
		slicedArray = append(slicedArray, val)
	}
	if includeLength {
		slicedArray = append(slicedArray, uint32(len(inputString)))
	}
	return slicedArray
}

// 将元素为 uint32 格式的数组打包成字符串
func UnsliceString(inputArray []uint32, includeLength bool) string {
	var arrayLenInByte int = (len(inputArray) - 1) * 4
	if includeLength {
		lastElementInArray := int(inputArray[len(inputArray)-1])
		if lastElementInArray < arrayLenInByte-3 || lastElementInArray > arrayLenInByte {
			return ""
		}
		arrayLenInByte = lastElementInArray
	}
	var buf bytes.Buffer
	for i := 0; i < len(inputArray); i++ {
		buf.WriteByte(byte(inputArray[i] & 0xff))
		buf.WriteByte(byte((inputArray[i] >> 8) & 0xff))
		buf.WriteByte(byte((inputArray[i] >> 16) & 0xff))
		buf.WriteByte(byte((inputArray[i] >> 24) & 0xff))
	}
	if includeLength {
		return buf.String()[:arrayLenInByte]
	}
	return buf.String()
}

func XXTEA(s, token string) string {
	if s == "" {
		return ""
	}
	data := SliceString(s, true)
	key := SliceString(token, false)
	for len(key) < 4 {
		key = append(key, 0)
	}
	n := len(data)
	if n == 0 {
		return ""
	}
	prev := data[n-1]
	const delta uint32 = 0x9E3779B9
	rounds := 6 + 52/n
	var sum uint32 = 0

	for rounds > 0 {
		rounds--
		sum = (sum + delta)
		eIdx := (sum >> 2) & 3

		for idx := 0; idx < n; idx++ {
			nextVal := data[(idx+1)%n]
			var mix uint32 = (prev >> 5) ^ (nextVal << 2)
			xorPart := (nextVal >> 3) ^ (prev << 4) ^ (sum ^ nextVal)
			mix += xorPart
			keyIdx := (idx & 3) ^ int(eIdx)
			mix += (key[keyIdx] ^ prev)
			data[idx] += mix
			prev = data[idx]
		}
	}
	return UnsliceString(data, false)
}

// 非标准的换表 Base 64
func CustomBase64Encode(s string) string {
	std := base64.StdEncoding.EncodeToString([]byte(s))
	var out strings.Builder
	for i := 0; i < len(std); i++ {
		if std[i] == '=' {
			out.WriteByte('=')
		} else {
			idx := strings.IndexByte(standardBase64CharList, std[i])
			out.WriteByte(customBase64CharList[idx])
		}
	}
	return out.String()
}
