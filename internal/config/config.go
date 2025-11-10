// 配置文件的读取和保存

package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 配置文件内容结构体
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

// 相关文件路径结构体
type Paths struct {
	ConfigDir  string
	ConfigFile string
	LogDir     string
	LogFile    string
}

var (
	// 默认配置
	DefaultConfig = map[string]interface{}{
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

	// 不同区域的网络配置
	Locations = map[string]map[string]interface{}{
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
)

// 初始化路径
func InitPaths() Paths {
	var paths Paths
	paths.ConfigDir = "../../configs"
	paths.LogDir = "../../log"
	paths.ConfigFile = filepath.Join(paths.ConfigDir, "srun_login.conf")
	paths.LogFile = filepath.Join(paths.LogDir, "srun_login.log")
	return paths
}

// 读取解析配置文件
func LoadConfig(configFile string) Config {
	configMap := make(map[string]string)
	if _, err := os.Stat(configFile); err == nil {
		configRawData, err := os.ReadFile(configFile)
		if err == nil {
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
				if _, ok := DefaultConfig[key]; ok {
					configMap[key] = val
				}
			}
		}
	}
	return parseConfigFromMap(configMap)
}

// 将配置写入文件
func SaveConfig(c Config, configFile string) error {
	if _, err := os.Stat(configFile); err == nil {
		backup := configFile + ".backup"
		copyFile(configFile, backup)
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
	writeKV("location", c.Location, "Location (dormitory/teaching)")

	return os.WriteFile(configFile, []byte(b.String()), 0644)
}

// 验证本地配置文件是否合法
func ValidateConfig(c Config) bool {
	return c.Username != "" && c.Password != "" && c.LoginHost != ""
}

func parseConfigFromMap(configMap map[string]string) Config {
	return Config{
		Username:      asStringOrDefault(configMap["username"], DefaultConfig["username"].(string)),
		Password:      asStringOrDefault(configMap["password"], DefaultConfig["password"].(string)),
		LoginHost:     asStringOrDefault(configMap["login_host"], DefaultConfig["login_host"].(string)),
		AutoReconnect: asBoolOrDefault(configMap["auto_reconnect"], DefaultConfig["auto_reconnect"].(bool)),
		CheckInterval: asIntOrDefault(configMap["check_interval"], DefaultConfig["check_interval"].(int)),
		CheckURL:      asStringOrDefault(configMap["check_url"], DefaultConfig["check_url"].(string)),
		RetryInterval: asIntOrDefault(configMap["retry_interval"], DefaultConfig["retry_interval"].(int)),
		MaxRetryTimes: asIntOrDefault(configMap["max_retry_times"], DefaultConfig["max_retry_times"].(int)),
		DebugMode:     asBoolOrDefault(configMap["debug_mode"], DefaultConfig["debug_mode"].(bool)),
		NetworkType:   asStringOrDefault(configMap["network_type"], DefaultConfig["network_type"].(string)),
		Location:      asStringOrDefault(configMap["location"], DefaultConfig["location"].(string)),
	}
}

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
	return err
}
