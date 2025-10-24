// 提供认证服务

package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"


	"github.com/sadak-x/srungo/internal/config"
	"github.com/sadak-x/srungo/internal/crypto"
	"github.com/sadak-x/srungo/internal/logger"
	"github.com/sadak-x/srungo/internal/network"
)

// 服务结构体
type Service struct {
	Config     *config.Config
	Logger     *logger.Logger
	NetClient  *network.Client
	RetryCount int
}

// 创建一个新的认证服务
func NewService(cfg *config.Config, log *logger.Logger) *Service {
	return &Service{
		Config:     cfg,
		Logger:     log,
		NetClient:  network.NewClient(cfg.LoginHost, cfg.Location),
		RetryCount: 0,
	}
}

// 加密用户信息
func (s *Service) getEncodedUserInfo(info network.Info, token string) string {
	jsonBytes, _ := json.Marshal(info)
	jsonString := string(jsonBytes)
	encoded := "{SRBX1}" + crypto.CustomBase64Encode(crypto.XXTEA(jsonString, token))
	return encoded
}

// 进行一次性登录流程
func (s *Service) LoginOnce() (bool, error) {
	loginParams, err := s.NetClient.GetLoginParams()
	if err != nil {
		s.Logger.Warn("Failed to get login parameters: "+err.Error(), true)
		loginParams = map[string]string{"ac_id": "5", "ip": ""}
	}

	loginParamsJson, _ := json.Marshal(loginParams)
	s.Logger.Debug("Got login parameters: "+string(loginParamsJson), true)

	username := s.Config.Username
	initInfo, err := s.NetClient.GetChallengeInfo(username, loginParams["ip"])
	if err != nil {
		s.Logger.Error("Failed to get initialization information: "+err.Error(), true)
		return false, err
	}

	initJson, _ := json.Marshal(initInfo)
	s.Logger.Debug("Got initialization information: "+string(initJson), true)

	token := initInfo["challenge"].(string)

	var ip string
	if loginParams["ip"] != "" {
		ip = loginParams["ip"]
	} else {
		ip = initInfo["client_ip"].(string)
	}

	hmd5 := crypto.MD5Hex(s.Config.Password, token)

	info := network.Info{
		Username: username,
		Password: s.Config.Password,
		IP:       ip,
		Acid:     loginParams["ac_id"],
		EncVer:   "srun_bx1",
	}

	encodedUser := s.getEncodedUserInfo(info, token)

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
	checksum := crypto.SHA1Hex(sb.String())

	loginResult, err := s.NetClient.Login(info, token, hmd5, encodedUser, checksum)
	resultJson, _ := json.Marshal(loginResult)
	if err == nil {
		s.Logger.Debug("Login result: "+string(resultJson), true)
		return true, err
	}
	return false, err
}

// 允许自动重连时，循环检测网络并在掉线时登录
func (s *Service) StartLoginLoop() {
	s.Logger.Info("Starting login monitoring...", true)
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Logger.Error(fmt.Sprintf("Panic in login loop: %v", r), true)
					time.Sleep(time.Duration(s.Config.RetryInterval) * time.Second)
				}
			}()

			isConnected := s.NetClient.CheckInternet(s.Config.CheckURL)
			if !isConnected && s.Config.AutoReconnect {
				s.Logger.Warn("Network disconnected, attempting to reconnect...", true)
				ok, _ := s.LoginOnce()
				if ok {
					s.Logger.Info("Reconnection successful", true)
					s.RetryCount = 0
				} else {
					s.RetryCount++
					if s.Config.MaxRetryTimes > 0 && s.RetryCount >= s.Config.MaxRetryTimes {
						s.Logger.Error("Maximum retry attempts reached, stopping reconnection", true)
						return
					}
					s.Logger.Warn(fmt.Sprintf("Login failed, retrying in %d seconds... (Attempt %d)",
						s.Config.RetryInterval, s.RetryCount), true)
					time.Sleep(time.Duration(s.Config.RetryInterval) * time.Second)
				}
			} else {
				if s.Config.DebugMode {
					s.Logger.Debug("Network connection check passed", true)
				}
				time.Sleep(time.Duration(s.Config.CheckInterval) * time.Second)
			}
		}()
	}
}
