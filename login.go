// login.go
package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// 可选的日志等级
const (
	LOG_DEBUG = "DEBUG"
	LOG_INFO  = "INFO"
	LOG_WARN  = "WARN"
	LOG_ERROR = "ERROR"
)

var (
	// 默认登录配置
	DEFAULT_CONFIG = map[string]interface{}{
		"username":        "",
		"password":        "",
		"login_host":      "222.204.3.154",
		"auto_reconnect":  true,
		"check_interval":  60,
		"check_url":       "https://www.bing.com",
		"retry_interval":  30,
		"max_retry_times": 0,
		"debug_mode":      false,
		"network_type":    "",
		"location":        "",
	}

	// 网络区域配置
	LOCATIONS = map[string]map[string]interface{}{
		"teaching": {
			"name":             "教学区(NCUWLAN)",
			"login_host":       "222.204.3.221",
			"needsNetworkType": false,
		},
		"dormitory": {
			"name":             "宿舍区(NCU-5G)",
			"login_host":       "222.204.3.154",
			"needsNetworkType": true,
		},
	}
	// 配置文件路径全局变量
	CONFIG_DIR  string
	CONFIG_FILE string
	LOG_DIR     string
	LOG_FILE    string
	config      Config
	httpClient  *http.Client

	// 后面用到的换表base64的表
	customBase64CharList   = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	standardBase64CharList = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

type Config struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	LoginHost     string `json:"login_host"`
	AutoReconnect bool   `json:"auto_reconnect"`
	CheckInterval int    `json:"check_interval"`
	CheckURL      string `json:"check_url"`
	RetryInterval int    `json:"retry_interval"`
	MaxRetryTimes int    `json:"max_retry_times"`
	DebugMode     bool   `json:"debug_mode"`
	NetworkType   string `json:"network_type"`
	Location      string `json:"location"`
}

type Info struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	Acid     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

// 初始化配置文件以及日志路径
func initPaths() {
	if runtime.GOOS == "windows" {
		CONFIG_DIR = `C:\etc`
		LOG_DIR = `C:\logs`
	} else {
		CONFIG_DIR = "./etc"
		LOG_DIR = "./log"
	}
	CONFIG_FILE = filepath.Join(CONFIG_DIR, "srun_login.conf")
	LOG_FILE = filepath.Join(LOG_DIR, "srun_login.log")
}

// 确保路径可读写，因权限问题出现选定路径不可读写时报错
func ensureDirectoryExists(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to create directory %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
}

// 格式化写入日志
func logMessage(message string, level string, showConsole bool) {
	timestamp := time.Now().Format(time.RFC3339)
	logLine := fmt.Sprintf("%s [%s] %s\n", timestamp, level, message)
	// 添加到日志文件尾
	logFile, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile.WriteString(logLine)
		logFile.Close()
	} else {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to write log file: %v\n", err)
	}
	// 控制台同步输出
	if showConsole || level == LOG_ERROR || (config.DebugMode && level == LOG_DEBUG) {
		if level == LOG_ERROR {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", level, message)
		} else {
			fmt.Printf("[%s] %s\n", level, message)
		}
	}
}

// 读取配置文件中的配置，转换为 Config 结构体方便处理
func parseConfigFromMap(configMap map[string]string) Config {
	c := Config{
		Username:      asStringOrDefault(configMap["username"], DEFAULT_CONFIG["username"].(string)),
		Password:      asStringOrDefault(configMap["password"], DEFAULT_CONFIG["password"].(string)),
		LoginHost:     asStringOrDefault(configMap["login_host"], DEFAULT_CONFIG["login_host"].(string)),
		AutoReconnect: asBoolOrDefault(configMap["auto_reconnect"], DEFAULT_CONFIG["auto_reconnect"].(bool)),
		CheckInterval: asIntOrDefault(configMap["check_interval"], DEFAULT_CONFIG["check_interval"].(int)),
		CheckURL:      asStringOrDefault(configMap["check_url"], DEFAULT_CONFIG["check_url"].(string)),
		RetryInterval: asIntOrDefault(configMap["retry_interval"], DEFAULT_CONFIG["retry_interval"].(int)),
		MaxRetryTimes: asIntOrDefault(configMap["max_retry_times"], DEFAULT_CONFIG["max_retry_times"].(int)),
		DebugMode:     asBoolOrDefault(configMap["debug_mode"], DEFAULT_CONFIG["debug_mode"].(bool)),
		NetworkType:   asStringOrDefault(configMap["network_type"], DEFAULT_CONFIG["network_type"].(string)),
		Location:      asStringOrDefault(configMap["location"], DEFAULT_CONFIG["location"].(string)),
	}
	return c
}

// parseConfigFromMap函数用到的一些工具函数
func asStringOrDefault(v string, def string) string {
	if v == "" {
		return def
	}
	return v
}
func asBoolOrDefault(v string, def bool) bool {
	if v == "" {
		return def
	}
	l := strings.ToLower(v)
	if l == "true" || l == "1" || l == "y" || l == "yes" {
		return true
	}
	if l == "false" || l == "0" || l == "n" || l == "no" {
		return false
	}
	return def
}
func asIntOrDefault(v string, def int) int {
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// 读取配置文件，返回包含配置文件内容的 Config 结构体
func loadConfig() Config {
	configMap := make(map[string]string)
	if _, err := os.Stat(CONFIG_FILE); err == nil {
		configRawData, err := os.ReadFile(CONFIG_FILE)
		if err != nil {
			logMessage("Failed to read configuration file: "+err.Error(), LOG_ERROR, true)
			return parseConfigFromMap(configMap)
		}
		scanner := bufio.NewScanner(bytes.NewReader(configRawData))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if _, ok := DEFAULT_CONFIG[key]; ok {
				configMap[key] = val
			}
		}
	}
	return parseConfigFromMap(configMap)
}

// 从用户输入中保存登录配置
func saveConfig(c Config) error {
	// 如果本地配置文件存在，但是内容不可解析
	// 我们无法直接用原来的配置文件名
	// 所以将原来的文件保存为备份文件
	if _, err := os.Stat(CONFIG_FILE); err == nil {
		backup := CONFIG_FILE + ".backup"
		copyFile(CONFIG_FILE, backup)
	}
	var b strings.Builder
	b.WriteString("# Srun Login Configuration File\n")
	b.WriteString(fmt.Sprintf("# Last updated: %s\n\n", time.Now().Format(time.RFC3339)))

	writeKV := func(key string, value interface{}, desc string) {
		b.WriteString(fmt.Sprintf("# %s\n", desc))
		b.WriteString(fmt.Sprintf("%s=%v\n\n", key, value))
	}
	writeKV("username", c.Username, "Student ID with network type suffix (e.g., 12345678@cmcc)")
	writeKV("password", c.Password, "Login password")
	writeKV("login_host", c.LoginHost, "Login server IP address")
	writeKV("auto_reconnect", c.AutoReconnect, "Enable automatic reconnection (true/false)")
	writeKV("check_interval", c.CheckInterval, "Network check interval in seconds")
	writeKV("check_url", c.CheckURL, "URL used for network connection test")
	writeKV("retry_interval", c.RetryInterval, "Interval between retry attempts in seconds")
	writeKV("max_retry_times", c.MaxRetryTimes, "Maximum number of retry attempts (0 for unlimited)")
	writeKV("debug_mode", c.DebugMode, "Enable debug logging (true/false)")
	writeKV("network_type", c.NetworkType, "Campus network type (cmcc/ndcard/unicom/ncu)")
	err := os.WriteFile(CONFIG_FILE, []byte(b.String()), 0644)
	if err == nil {
		logMessage("Configuration saved to: "+CONFIG_FILE, LOG_INFO, true)
	}
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

// 确保当前配置文件存在并且有效
func validateConfig(c Config) bool {
	return c.Username != "" && c.Password != "" && c.LoginHost != ""
}

// 在控制台中交互式获取用户输入的登录信息
func promptInteractiveConfig() Config {
	logMessage("Configuration file not found or incomplete, starting interactive setup...", LOG_INFO, true)
	reader := bufio.NewReader(os.Stdin)
	var username string
	for {
		fmt.Print("Please enter your student ID: ")
		s, _ := reader.ReadString('\n')
		username = strings.TrimSpace(s)
		if regexp.MustCompile(`^\d+$`).MatchString(username) {
			break
		}
		logMessage("Invalid input: Please enter numbers only", LOG_ERROR, true)
	}
	fmt.Println("\nSelect your location:")
	fmt.Println("1. Teaching Area (NCUWLAN 222.204.3.221)")
	fmt.Println("2. Dormitory Area (NCU-5G 222.204.3.154)")
	var location string
	var networkType string
	var loginHost string
	for {
		fmt.Print("Enter number (1-2): ")
		choiceRaw, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(choiceRaw)
		if choice == "1" {
			location = "teaching"
			loginHost = LOCATIONS["teaching"]["login_host"].(string)
			break
		} else if choice == "2" {
			location = "dormitory"
			loginHost = LOCATIONS["dormitory"]["login_host"].(string)
			// ask network type
			fmt.Println("\nSelect your campus network type:")
			networkTypes := []string{"cmcc", "ndcard", "unicom", "ncu"}
			for i, t := range networkTypes {
				fmt.Printf("%d. %s\n", i+1, t)
			}
			for {
				fmt.Print("Enter number (1-4): ")
				netChoiceRaw, _ := reader.ReadString('\n')
				netChoice := strings.TrimSpace(netChoiceRaw)
				if regexp.MustCompile(`^[1-4]$`).MatchString(netChoice) {
					idx, _ := strconv.Atoi(netChoice)
					networkType = networkTypes[idx-1]
					break
				}
				logMessage("Invalid choice: Please enter a number between 1 and 4", LOG_ERROR, true)
			}
			break
		} else {
			logMessage("Invalid choice: Please enter 1 or 2", LOG_ERROR, true)
		}
	}
	// 无回显输入密码
	fmt.Print("Please enter your password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		logMessage("Failed to read password: "+err.Error(), LOG_ERROR, true)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(bytePassword))
	if password == "" {
		logMessage("Password cannot be empty", LOG_ERROR, true)
		os.Exit(1)
	}
	// auto_reconnect
	autoReconnect := true
	for {
		fmt.Print("Enable auto reconnect? [y/N]: ")
		ansRaw, _ := reader.ReadString('\n')
		ans := strings.TrimSpace(strings.ToLower(ansRaw))
		if ans == "" || ans == "n" {
			autoReconnect = false
			break
		} else if ans == "y" {
			autoReconnect = true
			break
		}
		logMessage("Invalid input: Please enter Y or n", LOG_ERROR, true)
	}
	var fullUsername string
	if location == "teaching" {
		fullUsername = username
	} else {
		fullUsername = fmt.Sprintf("%s@%s", username, networkType)
	}
	config := Config{
		Username:      fullUsername,
		Password:      password,
		LoginHost:     loginHost,
		AutoReconnect: autoReconnect,
		CheckInterval: DEFAULT_CONFIG["check_interval"].(int),
		CheckURL:      DEFAULT_CONFIG["check_url"].(string),
		RetryInterval: DEFAULT_CONFIG["retry_interval"].(int),
		MaxRetryTimes: DEFAULT_CONFIG["max_retry_times"].(int),
		DebugMode:     DEFAULT_CONFIG["debug_mode"].(bool),
		NetworkType:   networkType,
		Location:      location,
	}
	if err := saveConfig(config); err != nil {
		logMessage("Failed to save configuration: "+err.Error(), LOG_ERROR, true)
		os.Exit(1)
	}
	logMessage("Configuration saved successfully", LOG_INFO, true)
	return config
}

// 允许自动重连时，检查互联网连接
func checkInternet() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(config.CheckURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// 加密过程 md5
func md5Hex(password, token string) string {
	sum := md5.Sum([]byte(token + password))
	return hex.EncodeToString(sum[:])
}

// 加密过程 sha1
func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// 将字符串切分成元素为 uint32 格式的数组
func sliceString(inputString string, includeLength bool) []uint32 {
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
func unsliceString(inputArray []uint32, includeLength bool) string {
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

func xxtea(s, token string) string {
	if s == "" {
		return ""
	}
	// 将字符串按 32-bit 小端切分
	data := sliceString(s, true)
	key := sliceString(token, false)
	// 兼容性填充 key 长度（原实现也这么做）
	for len(key) < 4 {
		key = append(key, 0)
	}
	n := len(data)
	if n == 0 {
		return ""
	}
	// 初始化 prev 为数组最后一个元素
	prev := data[n-1]
	// TEA 常量，It's a magic number~~
	const delta uint32 = 0x9E3779B9
	// 轮数，“52” 只是一个设计参数，让轮数在不同长度的块数据上都足够大。
	rounds := 6 + 52/n
	var sum uint32 = 0

	for rounds > 0 {
		rounds--
		sum = (sum + delta)
		// eIdx 用于从 key 中选择子项
		eIdx := (sum >> 2) & 3

		for idx := 0; idx < n; idx++ {
			// 环形地取下一个元素（下标越界自动回到 0）
			nextVal := data[(idx+1)%n]

			// 先计算初始移位/异或部分
			var mix uint32 = (prev >> 5) ^ (nextVal << 2)

			// 计算 xorPart
			xorPart := (nextVal >> 3) ^ (prev << 4) ^ (sum ^ nextVal)
			mix += xorPart

			// 加上 key 部分
			keyIdx := (idx & 3) ^ int(eIdx)
			mix += (key[keyIdx] ^ prev)

			// 更新当前元素
			data[idx] += mix

			// 更新 prev 以供下一次迭代使用
			prev = data[idx]
		}
	}
	// 将切分的 uint32 数组还原为字符串并返回
	return unsliceString(data, false)
}

// 换表 Base 64 加密
// 更换了 64 进制的字母表，使用自定义的版本进行加密
func customBase64Encode(s string) string {
	// 先使用标准 Base 64 进行加密
	std := base64.StdEncoding.EncodeToString([]byte(s))
	// 再用标准加密的结果作为索引反查自定义字母表中的字符
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

func getEncodedUserInfo(info Info, token string) string {
	jsonBytes, _ := json.Marshal(info)
	jsonString := string(jsonBytes)
	encoded := "{SRBX1}" + customBase64Encode(xxtea(jsonString, token))
	return encoded
}

// 获取登录信息，主要是ac_id和ip
func getLoginParams() (map[string]string, error) {
	result := make(map[string]string)
	urlStr := fmt.Sprintf("http://%s", config.LoginHost)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return result, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	finalURL := resp.Request.URL
	for k, v := range finalURL.Query() {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	// 如果没有给ac_id就用默认的
	if _, ok := result["ac_id"]; !ok {
		if config.Location == "teaching" {
			result["ac_id"] = "39"
		} else {
			result["ac_id"] = "5"
		}
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`<input[^>]*name="user_ip"[^>]*value="([^"]+)"`)
	m := re.FindSubmatch(bodyBytes)
	if len(m) >= 2 {
		result["ip"] = string(m[1])
	} else {
		result["ip"] = ""
	}
	return result, nil
}

// 向登录服务器请求 challenge 字段的信息，需要向服务器传递三个参数
// 其中 callback 参数的值是任意非空字符串
func getChallengeInfo(username, ip string) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	base := fmt.Sprintf("http://%s/cgi-bin/get_challenge", config.LoginHost)
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("username", username)
	q.Set("ip", ip)
	q.Set("callback", "callback")
	u.RawQuery = q.Encode()
	resp, err := httpClient.Get(u.String())
	if err != nil {
		return ret, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if err := json.Unmarshal(b, &ret); err != nil {
		// 返回是以 callback(...) 的形式给出的，需要去掉头尾的一点无关内容才能解析 json
		re := regexp.MustCompile(`\{.*\}`)
		m := re.Find(b)
		if m != nil {
			json.Unmarshal(m, &ret)
			return ret, nil
		}
		return ret, errors.New("failed to parse get_challenge response")
	}
	return ret, nil
}

func loginOnce() (bool, error) {

	loginParams, err := getLoginParams()
	if err != nil {
		logMessage("Failed to get login parameters: "+err.Error(), LOG_WARN, true)
		loginParams = map[string]string{"ac_id": "5", "ip": ""}
	}
	loginParamsJson, _ := json.Marshal(loginParams)
	logMessage("Got login parameters: "+string(loginParamsJson), LOG_INFO, true)

	username := config.Username
	initInfo, err := getChallengeInfo(username, loginParams["ip"])
	if err != nil {
		logMessage("Failed to get initialization information: "+err.Error(), LOG_ERROR, true)
		return false, err
	}
	initJson, _ := json.Marshal(initInfo)
	logMessage("Got initialization information: "+string(initJson), LOG_INFO, true)

	token := initInfo["challenge"].(string)

	var ip string
	if loginParams["ip"] != "" {
		ip = loginParams["ip"]
	} else {
		ip = initInfo["client_ip"].(string)
	}

	// 使用 challenge token 加密用户密码
	hmd5 := md5Hex(config.Password, token)

	info := Info{
		Username: username,
		Password: config.Password,
		IP:       ip,
		Acid:     loginParams["ac_id"],
		EncVer:   "srun_bx1",
	}

	encodedUser := getEncodedUserInfo(info, token)

	var sb strings.Builder
	sb.WriteString(token)
	sb.WriteString(username)
	sb.WriteString(token)
	sb.WriteString(hmd5)
	sb.WriteString(token)
	sb.WriteString(loginParams["ac_id"])
	sb.WriteString(token)
	sb.WriteString(ip)
	sb.WriteString(token)
	sb.WriteString("200")
	sb.WriteString(token)
	sb.WriteString("1")
	sb.WriteString(token)
	sb.WriteString(encodedUser)
	checksum := sha1Hex(sb.String())

	// 所有信息加密完成，向服务器发送登录请求
	loginUrl := fmt.Sprintf("http://%s/cgi-bin/srun_portal", config.LoginHost)
	u, _ := url.Parse(loginUrl)

	q := u.Query()
	q.Set("callback", "callback")
	q.Set("action", "login")
	q.Set("username", username)
	q.Set("password", "{MD5}"+hmd5)
	q.Set("os", "Windows 10")
	q.Set("name", "Windows")
	q.Set("nas_ip", "")
	q.Set("double_stack", "0")
	q.Set("chksum", checksum)
	q.Set("info", encodedUser)
	q.Set("ac_id", loginParams["ac_id"])
	q.Set("ip", ip)
	q.Set("n", "200")
	q.Set("type", "1")
	q.Set("capchaVal", "")
	q.Set("_", strconv.FormatInt(time.Now().UnixMicro(), 10))
	q.Set("double_stack", "0")
	u.RawQuery = q.Encode()

	resp, err := httpClient.Get(u.String())
	if err != nil {
		logMessage("Login request failed: "+err.Error(), LOG_ERROR, true)
		return false, err
	}
	defer resp.Body.Close()
	// 解析结果
	bRaw, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(`\{.*\}`)
	b := re.Find(bRaw)
	logMessage("Login result: "+string(b), LOG_INFO, true)
	var res map[string]interface{}
	json.Unmarshal(b, &res)
	if err := res["error"].(string); err == "ok" {
		return true, nil
	}
	return false, errors.New("auth failed")
}

func startLoginLoop() {
	retryCount := 0
	logMessage("Starting login monitoring...", LOG_INFO, true)
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logMessage(fmt.Sprintf("Panic in login loop: %v", r), LOG_ERROR, true)
					time.Sleep(time.Duration(config.RetryInterval) * time.Second)
				}
			}()
			isConnected := checkInternet()
			if !isConnected && config.AutoReconnect {
				logMessage("Network disconnected, attempting to reconnect...", LOG_WARN, true)
				ok, _ := loginOnce()
				if ok {
					logMessage("Reconnection successful", LOG_INFO, true)
					retryCount = 0
				} else {
					retryCount++
					if config.MaxRetryTimes > 0 && retryCount >= config.MaxRetryTimes {
						logMessage("Maximum retry attempts reached, stopping reconnection", LOG_ERROR, true)
						os.Exit(1)
					}
					logMessage(fmt.Sprintf("Login failed, retrying in %d seconds... (Attempt %d)", config.RetryInterval, retryCount), LOG_WARN, true)
					time.Sleep(time.Duration(config.RetryInterval) * time.Second)
				}
			} else {
				if config.DebugMode {
					logMessage("Network connection check passed", LOG_DEBUG, true)
				}
				time.Sleep(time.Duration(config.CheckInterval) * time.Second)
			}
		}()
	}
}

func main() {
	initPaths()
	ensureDirectoryExists(CONFIG_DIR)
	ensureDirectoryExists(LOG_DIR)

	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	// 读取本地配置
	config = loadConfig()

	// 如果本地没有配置或者配置文件不合理
	if !validateConfig(config) {
		config = promptInteractiveConfig()
	}
	logMessage("Starting Srun login client...", LOG_INFO, true)
	logMessage("Configured for user: "+config.Username, LOG_INFO, true)
	if config.AutoReconnect {
		logMessage("Auto reconnect enabled", LOG_INFO, true)
		startLoginLoop()
	} else {
		logMessage("Running in single login mode", LOG_INFO, true)
		if result, err := loginOnce(); result {
			logMessage("Login successful!", LOG_INFO, true)
		} else {
			logMessage("Login failed! Error message: "+err.Error(), LOG_ERROR, true)
		}
	}
}
