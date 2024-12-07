// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2016 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	errInvalidDSNUnescaped       = errors.New("invalid DSN: did you forget to escape a param value?")
	errInvalidDSNAddr            = errors.New("invalid DSN: network address not terminated (missing closing brace)")
	errInvalidDSNNoSlash         = errors.New("invalid DSN: missing the slash separating the database name")
	errInvalidDSNUnsafeCollation = errors.New("invalid DSN: interpolateParams can not be used with unsafe collations")
)

// Config is a configuration parsed from a DSN string.
// If a new Config is created instead of being parsed from a DSN string,
// the NewConfig function should be used, which sets default values.
type Config struct {
	// 基础连接信息
	User   string // 数据库用户名
	Passwd string // 数据库密码(需要配合User使用)
	Net    string // 网络类型 (如 "tcp", "tcp6", "unix"，默认为 "tcp")
	Addr   string // 连接地址 (tcp默认为 "127.0.0.1:3306"，unix默认为 "/tmp/mysql.sock")
	DBName string // 数据库名称

	// 连接参数和属性
	Params               map[string]string // 额外的连接参数，键值对形式
	ConnectionAttributes string            // 连接属性，以逗号分隔的"key:value"对
	charsets             []string          // 连接字符集，会通过 SET NAMES <charset> 设置
	Collation            string            // 字符排序规则，会通过 SET NAMES <charset> COLLATE <collation> 设置

	// 时间和位置相关
	Loc          *time.Location // 用于time.Time值的时区设置
	timeTruncate time.Duration  // time.Time值的截断精度

	// 网络和安全配置
	MaxAllowedPacket int         // 允许的最大数据包大小
	ServerPubKey     string      // 服务器公钥名称
	TLSConfig        string      // TLS配置名称
	TLS              *tls.Config // TLS配置对象，优先级高于TLSConfig

	// 超时设置
	Timeout      time.Duration // 连接超时时间
	ReadTimeout  time.Duration // I/O读取超时时间
	WriteTimeout time.Duration // I/O写入超时时间

	// 功能组件
	Logger   Logger                                                            // 日志记录器
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error) // 自定义连接创建函数

	// 布尔类型配置
	AllowAllFiles            bool // 是否允许使用LOAD DATA LOCAL INFILE加载所有文件
	AllowCleartextPasswords  bool // 是否允许明文密码认证插件
	AllowFallbackToPlaintext bool // 当服务器不支持TLS时是否允许降级为非加密连接
	AllowNativePasswords     bool // 是否允许原生密码认证方式
	AllowOldPasswords        bool // 是否允许旧的不安全密码方式
	CheckConnLiveness        bool // 使用连接前是否检查连接活跃性
	ClientFoundRows          bool // 是否返回匹配的行数而不是改变的行数
	ColumnsWithAlias         bool // 是否在列名前加表别名
	InterpolateParams        bool // 是否在查询字符串中插入占位符
	MultiStatements          bool // 是否允许在一个查询中执行多个语句
	ParseTime                bool // 是否自动解析时间值为time.Time
	RejectReadOnly           bool // 是否拒绝只读连接

	// 内部使用的非导出字段
	beforeConnect func(context.Context, *Config) error // 建立连接前的回调函数
	pubKey        *rsa.PublicKey                       // 服务器公钥对象
}

// Functional Options Pattern
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
type Option func(*Config) error

// NewConfig creates a new Config and sets default values.
func NewConfig() *Config {
	cfg := &Config{
		Loc:                  time.UTC,
		MaxAllowedPacket:     defaultMaxAllowedPacket,
		Logger:               defaultLogger,
		AllowNativePasswords: true,
		CheckConnLiveness:    true,
	}

	return cfg
}

// Apply applies the given options to the Config object.
func (c *Config) Apply(opts ...Option) error {
	for _, opt := range opts {
		err := opt(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// TimeTruncate sets the time duration to truncate time.Time values in
// query parameters.
func TimeTruncate(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.timeTruncate = d
		return nil
	}
}

// BeforeConnect sets the function to be invoked before a connection is established.
func BeforeConnect(fn func(context.Context, *Config) error) Option {
	return func(cfg *Config) error {
		cfg.beforeConnect = fn
		return nil
	}
}

func (cfg *Config) Clone() *Config {
	cp := *cfg
	if cp.TLS != nil {
		cp.TLS = cfg.TLS.Clone()
	}
	if len(cp.Params) > 0 {
		cp.Params = make(map[string]string, len(cfg.Params))
		for k, v := range cfg.Params {
			cp.Params[k] = v
		}
	}
	if cfg.pubKey != nil {
		cp.pubKey = &rsa.PublicKey{
			N: new(big.Int).Set(cfg.pubKey.N),
			E: cfg.pubKey.E,
		}
	}
	return &cp
}

func (cfg *Config) normalize() error {
	if cfg.InterpolateParams && cfg.Collation != "" && unsafeCollations[cfg.Collation] {
		return errInvalidDSNUnsafeCollation
	}

	// Set default network if empty
	if cfg.Net == "" {
		cfg.Net = "tcp"
	}

	// Set default address if empty
	if cfg.Addr == "" {
		switch cfg.Net {
		case "tcp":
			cfg.Addr = "127.0.0.1:3306"
		case "unix":
			cfg.Addr = "/tmp/mysql.sock"
		default:
			return errors.New("default addr for network '" + cfg.Net + "' unknown")
		}
	} else if cfg.Net == "tcp" {
		cfg.Addr = ensureHavePort(cfg.Addr)
	}

	if cfg.TLS == nil {
		switch cfg.TLSConfig {
		case "false", "":
			// don't set anything
		case "true":
			cfg.TLS = &tls.Config{}
		case "skip-verify":
			cfg.TLS = &tls.Config{InsecureSkipVerify: true}
		case "preferred":
			cfg.TLS = &tls.Config{InsecureSkipVerify: true}
			cfg.AllowFallbackToPlaintext = true
		default:
			cfg.TLS = getTLSConfigClone(cfg.TLSConfig)
			if cfg.TLS == nil {
				return errors.New("invalid value / unknown config name: " + cfg.TLSConfig)
			}
		}
	}

	if cfg.TLS != nil && cfg.TLS.ServerName == "" && !cfg.TLS.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err == nil {
			cfg.TLS.ServerName = host
		}
	}

	if cfg.ServerPubKey != "" {
		cfg.pubKey = getServerPubKey(cfg.ServerPubKey)
		if cfg.pubKey == nil {
			return errors.New("invalid value / unknown server pub key name: " + cfg.ServerPubKey)
		}
	}

	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}

	return nil
}

func writeDSNParam(buf *bytes.Buffer, hasParam *bool, name, value string) {
	buf.Grow(1 + len(name) + 1 + len(value))
	if !*hasParam {
		*hasParam = true
		buf.WriteByte('?')
	} else {
		buf.WriteByte('&')
	}
	buf.WriteString(name)
	buf.WriteByte('=')
	buf.WriteString(value)
}

// FormatDSN formats the given Config into a DSN string which can be passed to
// the driver.
//
// Note: use [NewConnector] and [database/sql.OpenDB] to open a connection from a [*Config].
func (cfg *Config) FormatDSN() string {
	var buf bytes.Buffer

	// [username[:password]@]
	if len(cfg.User) > 0 {
		buf.WriteString(cfg.User)
		if len(cfg.Passwd) > 0 {
			buf.WriteByte(':')
			buf.WriteString(cfg.Passwd)
		}
		buf.WriteByte('@')
	}

	// [protocol[(address)]]
	if len(cfg.Net) > 0 {
		buf.WriteString(cfg.Net)
		if len(cfg.Addr) > 0 {
			buf.WriteByte('(')
			buf.WriteString(cfg.Addr)
			buf.WriteByte(')')
		}
	}

	// /dbname
	buf.WriteByte('/')
	buf.WriteString(url.PathEscape(cfg.DBName))

	// [?param1=value1&...&paramN=valueN]
	hasParam := false

	if cfg.AllowAllFiles {
		hasParam = true
		buf.WriteString("?allowAllFiles=true")
	}

	if cfg.AllowCleartextPasswords {
		writeDSNParam(&buf, &hasParam, "allowCleartextPasswords", "true")
	}

	if cfg.AllowFallbackToPlaintext {
		writeDSNParam(&buf, &hasParam, "allowFallbackToPlaintext", "true")
	}

	if !cfg.AllowNativePasswords {
		writeDSNParam(&buf, &hasParam, "allowNativePasswords", "false")
	}

	if cfg.AllowOldPasswords {
		writeDSNParam(&buf, &hasParam, "allowOldPasswords", "true")
	}

	if !cfg.CheckConnLiveness {
		writeDSNParam(&buf, &hasParam, "checkConnLiveness", "false")
	}

	if cfg.ClientFoundRows {
		writeDSNParam(&buf, &hasParam, "clientFoundRows", "true")
	}

	if charsets := cfg.charsets; len(charsets) > 0 {
		writeDSNParam(&buf, &hasParam, "charset", strings.Join(charsets, ","))
	}

	if col := cfg.Collation; col != "" {
		writeDSNParam(&buf, &hasParam, "collation", col)
	}

	if cfg.ColumnsWithAlias {
		writeDSNParam(&buf, &hasParam, "columnsWithAlias", "true")
	}

	if cfg.InterpolateParams {
		writeDSNParam(&buf, &hasParam, "interpolateParams", "true")
	}

	if cfg.Loc != time.UTC && cfg.Loc != nil {
		writeDSNParam(&buf, &hasParam, "loc", url.QueryEscape(cfg.Loc.String()))
	}

	if cfg.MultiStatements {
		writeDSNParam(&buf, &hasParam, "multiStatements", "true")
	}

	if cfg.ParseTime {
		writeDSNParam(&buf, &hasParam, "parseTime", "true")
	}

	if cfg.timeTruncate > 0 {
		writeDSNParam(&buf, &hasParam, "timeTruncate", cfg.timeTruncate.String())
	}

	if cfg.ReadTimeout > 0 {
		writeDSNParam(&buf, &hasParam, "readTimeout", cfg.ReadTimeout.String())
	}

	if cfg.RejectReadOnly {
		writeDSNParam(&buf, &hasParam, "rejectReadOnly", "true")
	}

	if len(cfg.ServerPubKey) > 0 {
		writeDSNParam(&buf, &hasParam, "serverPubKey", url.QueryEscape(cfg.ServerPubKey))
	}

	if cfg.Timeout > 0 {
		writeDSNParam(&buf, &hasParam, "timeout", cfg.Timeout.String())
	}

	if len(cfg.TLSConfig) > 0 {
		writeDSNParam(&buf, &hasParam, "tls", url.QueryEscape(cfg.TLSConfig))
	}

	if cfg.WriteTimeout > 0 {
		writeDSNParam(&buf, &hasParam, "writeTimeout", cfg.WriteTimeout.String())
	}

	if cfg.MaxAllowedPacket != defaultMaxAllowedPacket {
		writeDSNParam(&buf, &hasParam, "maxAllowedPacket", strconv.Itoa(cfg.MaxAllowedPacket))
	}

	// other params
	if cfg.Params != nil {
		var params []string
		for param := range cfg.Params {
			params = append(params, param)
		}
		sort.Strings(params)
		for _, param := range params {
			writeDSNParam(&buf, &hasParam, param, url.QueryEscape(cfg.Params[param]))
		}
	}

	return buf.String()
}

// ParseDSN parses the DSN string to a Config
func ParseDSN(dsn string) (cfg *Config, err error) {
	// New config with some default values
	cfg = NewConfig()

	// [user[:password]@][net[(addr)]]/dbname[?param1=value1&paramN=valueN]
	// Find the last '/' (since the password or the net addr might contain a '/')
	foundSlash := false
	for i := len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			foundSlash = true
			var j, k int

			// left part is empty if i <= 0
			if i > 0 {
				// [username[:password]@][protocol[(address)]]
				// Find the last '@' in dsn[:i]
				for j = i; j >= 0; j-- {
					if dsn[j] == '@' {
						// username[:password]
						// Find the first ':' in dsn[:j]
						for k = 0; k < j; k++ {
							if dsn[k] == ':' {
								cfg.Passwd = dsn[k+1 : j]
								break
							}
						}
						cfg.User = dsn[:k]

						break
					}
				}

				// [protocol[(address)]]
				// Find the first '(' in dsn[j+1:i]
				for k = j + 1; k < i; k++ {
					if dsn[k] == '(' {
						// dsn[i-1] must be == ')' if an address is specified
						if dsn[i-1] != ')' {
							if strings.ContainsRune(dsn[k+1:i], ')') {
								return nil, errInvalidDSNUnescaped
							}
							return nil, errInvalidDSNAddr
						}
						cfg.Addr = dsn[k+1 : i-1]
						break
					}
				}
				cfg.Net = dsn[j+1 : k]
			}

			// dbname[?param1=value1&...&paramN=valueN]
			// Find the first '?' in dsn[i+1:]
			for j = i + 1; j < len(dsn); j++ {
				if dsn[j] == '?' {
					if err = parseDSNParams(cfg, dsn[j+1:]); err != nil {
						return
					}
					break
				}
			}

			dbname := dsn[i+1 : j]
			if cfg.DBName, err = url.PathUnescape(dbname); err != nil {
				return nil, fmt.Errorf("invalid dbname %q: %w", dbname, err)
			}

			break
		}
	}

	if !foundSlash && len(dsn) > 0 {
		return nil, errInvalidDSNNoSlash
	}

	if err = cfg.normalize(); err != nil {
		return nil, err
	}
	return
}

// parseDSNParams parses the DSN "query string"
// Values must be url.QueryEscape'ed
func parseDSNParams(cfg *Config, params string) (err error) {
	for _, v := range strings.Split(params, "&") {
		key, value, found := strings.Cut(v, "=")
		if !found {
			continue
		}

		// cfg params
		switch key {
		// Disable INFILE allowlist / enable all files
		case "allowAllFiles":
			var isBool bool
			cfg.AllowAllFiles, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Use cleartext authentication mode (MySQL 5.5.10+)
		case "allowCleartextPasswords":
			var isBool bool
			cfg.AllowCleartextPasswords, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Allow fallback to unencrypted connection if server does not support TLS
		case "allowFallbackToPlaintext":
			var isBool bool
			cfg.AllowFallbackToPlaintext, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Use native password authentication
		case "allowNativePasswords":
			var isBool bool
			cfg.AllowNativePasswords, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Use old authentication mode (pre MySQL 4.1)
		case "allowOldPasswords":
			var isBool bool
			cfg.AllowOldPasswords, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Check connections for Liveness before using them
		case "checkConnLiveness":
			var isBool bool
			cfg.CheckConnLiveness, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Switch "rowsAffected" mode
		case "clientFoundRows":
			var isBool bool
			cfg.ClientFoundRows, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// charset
		case "charset":
			cfg.charsets = strings.Split(value, ",")

		// Collation
		case "collation":
			cfg.Collation = value

		case "columnsWithAlias":
			var isBool bool
			cfg.ColumnsWithAlias, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Compression
		case "compress":
			return errors.New("compression not implemented yet")

		// Enable client side placeholder substitution
		case "interpolateParams":
			var isBool bool
			cfg.InterpolateParams, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Time Location
		case "loc":
			if value, err = url.QueryUnescape(value); err != nil {
				return
			}
			cfg.Loc, err = time.LoadLocation(value)
			if err != nil {
				return
			}

		// multiple statements in one query
		case "multiStatements":
			var isBool bool
			cfg.MultiStatements, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// time.Time parsing
		case "parseTime":
			var isBool bool
			cfg.ParseTime, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// time.Time truncation
		case "timeTruncate":
			cfg.timeTruncate, err = time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("invalid timeTruncate value: %v, error: %w", value, err)
			}

		// I/O read Timeout
		case "readTimeout":
			cfg.ReadTimeout, err = time.ParseDuration(value)
			if err != nil {
				return
			}

		// Reject read-only connections
		case "rejectReadOnly":
			var isBool bool
			cfg.RejectReadOnly, isBool = readBool(value)
			if !isBool {
				return errors.New("invalid bool value: " + value)
			}

		// Server public key
		case "serverPubKey":
			name, err := url.QueryUnescape(value)
			if err != nil {
				return fmt.Errorf("invalid value for server pub key name: %v", err)
			}
			cfg.ServerPubKey = name

		// Strict mode
		case "strict":
			panic("strict mode has been removed. See https://github.com/go-sql-driver/mysql/wiki/strict-mode")

		// Dial Timeout
		case "timeout":
			cfg.Timeout, err = time.ParseDuration(value)
			if err != nil {
				return
			}

		// TLS-Encryption
		case "tls":
			boolValue, isBool := readBool(value)
			if isBool {
				if boolValue {
					cfg.TLSConfig = "true"
				} else {
					cfg.TLSConfig = "false"
				}
			} else if vl := strings.ToLower(value); vl == "skip-verify" || vl == "preferred" {
				cfg.TLSConfig = vl
			} else {
				name, err := url.QueryUnescape(value)
				if err != nil {
					return fmt.Errorf("invalid value for TLS config name: %v", err)
				}
				cfg.TLSConfig = name
			}

		// I/O write Timeout
		case "writeTimeout":
			cfg.WriteTimeout, err = time.ParseDuration(value)
			if err != nil {
				return
			}
		case "maxAllowedPacket":
			cfg.MaxAllowedPacket, err = strconv.Atoi(value)
			if err != nil {
				return
			}

		// Connection attributes
		case "connectionAttributes":
			connectionAttributes, err := url.QueryUnescape(value)
			if err != nil {
				return fmt.Errorf("invalid connectionAttributes value: %v", err)
			}
			cfg.ConnectionAttributes = connectionAttributes

		default:
			// lazy init
			if cfg.Params == nil {
				cfg.Params = make(map[string]string)
			}

			if cfg.Params[key], err = url.QueryUnescape(value); err != nil {
				return
			}
		}
	}

	return
}

func ensureHavePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "3306")
	}
	return addr
}
