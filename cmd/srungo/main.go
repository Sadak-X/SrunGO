package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sadak-x/srungo/internal/auth"
	"github.com/sadak-x/srungo/internal/config"
	"github.com/sadak-x/srungo/internal/logger"
	"golang.org/x/term"
)

func ensureDirectoryExists(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to create directory %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
}

func promptInteractiveConfig(paths config.Paths, log *logger.Logger) config.Config {
	log.Info("Configuration file not found or incomplete, starting interactive setup...", true)
	reader := bufio.NewReader(os.Stdin)

	// Get student ID
	var username string
	for {
		fmt.Print("Please enter your student ID: ")
		s, _ := reader.ReadString('\n')
		username = strings.TrimSpace(s)
		if regexp.MustCompile(`^\d+$`).MatchString(username) {
			break
		}
		log.Error("Invalid input: Please enter numbers only", true)
	}

	// Select location
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
			loginHost = config.Locations["teaching"]["login_host"].(string)
			break
		} else if choice == "2" {
			location = "dormitory"
			loginHost = config.Locations["dormitory"]["login_host"].(string)
			// Ask network type
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
				log.Error("Invalid choice: Please enter a number between 1 and 4", true)
			}
			break
		} else {
			log.Error("Invalid choice: Please enter 1 or 2", true)
		}
	}

	fmt.Print("Please enter your password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Error("Failed to read password: "+err.Error(), true)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(bytePassword))
	if password == "" {
		log.Error("Password cannot be empty", true)
		os.Exit(1)
	}

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
		log.Error("Invalid input: Please enter Y or n", true)
	}

	var fullUsername string
	if location == "teaching" {
		fullUsername = username
	} else {
		fullUsername = fmt.Sprintf("%s@%s", username, networkType)
	}

	cfg := config.Config{
		Username:      fullUsername,
		Password:      password,
		LoginHost:     loginHost,
		AutoReconnect: autoReconnect,
		CheckInterval: config.DefaultConfig["check_interval"].(int),
		CheckURL:      config.DefaultConfig["check_url"].(string),
		RetryInterval: config.DefaultConfig["retry_interval"].(int),
		MaxRetryTimes: config.DefaultConfig["max_retry_times"].(int),
		DebugMode:     config.DefaultConfig["debug_mode"].(bool),
		NetworkType:   networkType,
		Location:      location,
	}

	if err := config.SaveConfig(cfg, paths.ConfigFile); err != nil {
		log.Error("Failed to save configuration: "+err.Error(), true)
		os.Exit(1)
	}

	log.Info("Configuration saved successfully", true)
	return cfg
}

func main() {
	// 初始化路径
	paths := config.InitPaths()
	ensureDirectoryExists(paths.ConfigDir)
	ensureDirectoryExists(paths.LogDir)

	// 加载配置
	cfg := config.LoadConfig(paths.ConfigFile)

	log := logger.New(paths.LogFile, cfg.DebugMode)

	// 如果本地的配置文件不存在，或存在但是内容不合法
	if !config.ValidateConfig(cfg) {
		cfg = promptInteractiveConfig(paths, log)
	}

	log.Info("Starting Srun login client...", true)
	log.Info("Configured for user: "+cfg.Username, true)

	// 创建认证服务
	authService := auth.NewService(&cfg, log)

	// 开始登录
	if cfg.AutoReconnect {
		log.Info("Auto reconnect enabled", true)
		authService.StartLoginLoop()
	} else {
		log.Info("Running in single login mode", true)
		if result, err := authService.LoginOnce(); result {
			log.Info("Login successful!", true)
		} else {
			log.Error("Login failed! Error message: "+err.Error(), true)
		}
	}
}
