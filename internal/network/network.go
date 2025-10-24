// 提供网络相关的操作

package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

type Info struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	Acid     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

type Client struct {
	HTTPClient *http.Client
	LoginHost  string
	Location   string
}

func NewClient(loginHost, location string) *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		LoginHost: loginHost,
		Location:  location,
	}
}

// 检查网络是否连通，使用配置文件中指定的网络 url
func (c *Client) CheckInternet(checkURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(checkURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// 获取登录参数（似乎不需要网络就能办到这一点，考虑重构）
func (c *Client) GetLoginParams() (map[string]string, error) {
	result := make(map[string]string)
	if c.Location == "teaching" {
		result["ac_id"] = "39"
	} else {
		result["ac_id"] = "5"
	}
	return result, nil
}

// 获取服务器返回的 challenger token
func (c *Client) GetChallengeInfo(username, ip string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	base := fmt.Sprintf("http://%s/cgi-bin/get_challenge", c.LoginHost)
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("username", username)
	q.Set("ip", ip)
	q.Set("callback", "callback")
	u.RawQuery = q.Encode()

	resp, err := c.HTTPClient.Get(u.String())
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &result); err != nil {
		re := regexp.MustCompile(`\{.*\}`)
		m := re.Find(b)
		if m != nil {
			json.Unmarshal(m, &result)
			return result, nil
		}
		return result, errors.New("failed to parse GetChallengeInfo response from server")
	}
	return result, nil
}

// 执行登录操作
func (c *Client) Login(info Info, token, hmd5, encodedUser, checksum string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	loginUrl := fmt.Sprintf("http://%s/cgi-bin/srun_portal", c.LoginHost)
	u, _ := url.Parse(loginUrl)

	q := u.Query()
	q.Set("callback", "callback")
	q.Set("action", "login")
	q.Set("username", info.Username)
	q.Set("password", "{MD5}"+hmd5)
	q.Set("os", "Windows 10")
	q.Set("name", "Windows")
	q.Set("nas_ip", "")
	q.Set("double_stack", "0")
	q.Set("chksum", checksum)
	q.Set("info", encodedUser)
	q.Set("ac_id", info.Acid)
	q.Set("ip", info.IP)
	q.Set("n", "200")
	q.Set("type", "1")
	q.Set("_", strconv.FormatInt(time.Now().UnixMicro(), 10))
	u.RawQuery = q.Encode()

	resp, err := c.HTTPClient.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &result); err != nil {
		re := regexp.MustCompile(`\{.*\}`)
		m := re.Find(b)
		if m != nil {
			json.Unmarshal(m, &result)
			return result, nil
		}
		return result, errors.New("failed to parse login response")
	}
	return result, nil
}
