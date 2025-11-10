# SrunGO

SrunGO 是一个用 Go 编写的深澜校园网自动登录客户端，支持交互式配置、自动重连与命令行参数登录。

## 主要特性

- 支持从配置文件加载用户信息（`etc/srun_login.conf`）
- 支持交互式初始配置（首次运行时）
- 支持命令行参数直接登录（CLI 优先级高于配置文件）
- 自动断线重连（还在写）
- 将服务器返回的原始响应记录为 DEBUG 日志，便于故障排查

## 目录结构（重要文件）

- `cmd/srungo/` - 程序主入口
- `internal/config/` - 配置加载与保存逻辑
- `internal/logger/` - 日志封装
- `internal/network/` - 与登录服务器交互的网络逻辑
- `internal/auth/` - 登录与重连控制逻辑
- `internal/cli/` - 命令行参数解析
- `etc/srun_login.conf` - 配置文件（运行后生成或由用户编辑）
- `log/srun_login.log` - 运行日志（默认位置）

## 安装与构建

系统要求：Go 1.20+

在项目根目录运行：

```bash
go build -o srungo ./cmd/srungo
```

或者直接运行：

```bash
go run ./cmd/srungo
```

## 使用方法

1. 交互式配置（首次运行或未配置时）

运行 `srungo`（或 `go run ./cmd/srungo`）后，如果没有找到有效配置，会进入交互式设置，提示输入学号、位置、密码等信息并保存到 `etc/srun_login.conf`。

1. 命令行参数直接登录（CLI 优先）

推荐用于脚本或一次性登录：

```bash
./srungo -u 8008122302 -p 'p@s5w0rd'
```

常用参数：

- `-u`, `-username`：用户名（学号）。在宿舍区需带上 `@network` 或同时传 `-n` 指定网络类型。
- `-p`, `-password`：密码
- `-host`, `-loginhost`：覆盖默认的登录服务器地址
- `-n`, `-networktype`：宿舍区网络类型（cmcc/ndcard/unicom/ncu）
- `-loc`, `-location`：位置（`teaching` 或 `dormitory`）
- `-r`, `-autoreconnect`：启用自动重连
- `-debug`, `-d`：启用调试日志（会输出服务器的原始响应）

一般而言，在南昌大学教学区使用本软件时，仅需指定学号、密码，位置为 `teaching` 即可。
在寝室区使用本软件时，需要除账号密码以外，位置须指定为 `dormitory`，并通过 `-n` 参数指定网络类型。其中ndcard表示电信，cmcc表示移动，unicom表示联通，ncu表示校园网，与深澜网页端一致。

示例：

```bash
# 单次登录
./srungo -u 8008122302 -p p@s5w0rd

# 指定宿舍网络类型并启用自动重连与调试
./srungo -u 8008122302 -p p@s5w0rd -loc dormitory -n ncu -r -debug

# 覆盖登录主机
./srungo -u 8008122302 -p p@s5w0rd -host 222.204.3.154
```

## 配置文件（`etc/srun_login.conf`）

若使用命令行输入登录参数，配置文件示例及说明会在首次运行时生成。关键字段：

- `username`：学号或带网络后缀的用户名（例如 `8008122302@ncu`）
- `password`：登录密码
- `login_host`：登录服务器 IP 或域名
- `auto_reconnect`：是否自动重连（true/false）
- `check_interval`：连接检查间隔（秒）
- `check_url`：用于检测网络连通性的 URL
- `retry_interval`：重试间隔（秒）
- `max_retry_times`：最大重试次数（0 表示无限）
- `debug_mode`：是否启用 debug 日志（true/false）

注意：命令行参数会覆盖配置文件中的相应字段。

## 日志

- 默认日志路径：`log/srun_login.log`
- INFO 级别记录运行信息
- ERROR 级别记录错误
DEBUG 级别（启用 `-debug` 或在配置中设置 `debug_mode=true`）会记录来自服务器的原始响应：

- Got login parameters (raw)
- Got initialization information (raw)
- Login result (raw)

这些原始响应帮助诊断与服务端的通信问题。

## 调试与常见问题

- 无法连接登录服务器：检查 `login_host` 是否正确，尝试 `-host` 指定
- 日志太多：关闭 `-debug` 或在配置文件中设置 `debug_mode=false`

## 许可

本项目使用Apache-2.0协议开源，欢迎使用和修改。
