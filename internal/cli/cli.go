package cli

import (
    "flag"
    "os"
)

// Args 存放从命令行解析出来的登录相关参数
type Args struct {
    Use          bool   // 是否使用命令行参数（最小要求：用户名和密码均提供）
    Username     string
    Password     string
    LoginHost    string
    NetworkType  string
    Location     string
    AutoReconnect bool
    DebugMode    bool
}

// ParseArgs 解析 os.Args 并返回 Args
func ParseArgs() Args {
    fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

    username := fs.String("u", "", "username (student id, may include @network)")
    password := fs.String("p", "", "password")
    host := fs.String("host", "", "login host (覆盖默认的 login host)")
    network := fs.String("n", "", "network type for dormitory (cmcc/ndcard/unicom/ncu)")
    loc := fs.String("loc", "", "location: teaching or dormitory")
    auto := fs.Bool("r", false, "enable auto reconnect")
    debug := fs.Bool("debug", false, "enable debug mode")

    // 允许常见长写法
    fs.StringVar(username, "username", "", "username (alias)")
    fs.StringVar(password, "password", "", "password (alias)")
    fs.StringVar(host, "loginhost", "", "login host (alias)")
    fs.StringVar(network, "networktype", "", "network type (alias)")
    fs.StringVar(loc, "location", "", "location (alias)")
    fs.BoolVar(auto, "autoreconnect", false, "enable auto reconnect (alias)")
    fs.BoolVar(debug, "d", false, "enable debug (alias)")

    // 解析参数（Ignore error 以便外层处理）
    _ = fs.Parse(os.Args[1:])

    use := *username != "" && *password != ""

    return Args{
        Use:           use,
        Username:      *username,
        Password:      *password,
        LoginHost:     *host,
        NetworkType:   *network,
        Location:      *loc,
        AutoReconnect: *auto,
        DebugMode:     *debug,
    }
}