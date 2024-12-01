// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2018 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"context"
	"database/sql/driver"
	"net"
	"os"
	"strconv"
	"strings"
)

// connector 结构体用于存储连接配置和编码后的连接属性
type connector struct {
	cfg               *Config // 不可变的私有配置副本
	encodedAttributes string  // 编码后的连接属性
}

// encodeConnectionAttributes 编码连接属性为字符串
func encodeConnectionAttributes(cfg *Config) string {
	// 创建用于存储连接属性的字节切片
	connAttrsBuf := make([]byte, 0)

	// 添加默认连接属性
	// 客户端名称
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrClientName)
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrClientNameValue)
	// 操作系统
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrOS)
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrOSValue)
	// 平台
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrPlatform)
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrPlatformValue)
	// 进程ID
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrPid)
	connAttrsBuf = appendLengthEncodedString(connAttrsBuf, strconv.Itoa(os.Getpid()))

	// 添加服务器主机信息
	serverHost, _, _ := net.SplitHostPort(cfg.Addr)
	if serverHost != "" {
		connAttrsBuf = appendLengthEncodedString(connAttrsBuf, connAttrServerHost)
		connAttrsBuf = appendLengthEncodedString(connAttrsBuf, serverHost)
	}

	// 添加用户定义的连接属性
	for _, connAttr := range strings.Split(cfg.ConnectionAttributes, ",") {
		k, v, found := strings.Cut(connAttr, ":")
		if !found {
			continue
		}
		connAttrsBuf = appendLengthEncodedString(connAttrsBuf, k)
		connAttrsBuf = appendLengthEncodedString(connAttrsBuf, v)
	}

	return string(connAttrsBuf)
}

// newConnector 创建一个新的连接器实例
func newConnector(cfg *Config) *connector {
	// 编码连接属性
	encodedAttributes := encodeConnectionAttributes(cfg)
	return &connector{
		cfg:               cfg,
		encodedAttributes: encodedAttributes,
	}
}

// Connect 实现 driver.Connector 接口
// Connect 返回一个到数据库的连接
func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	var err error

	// 如果存在beforeConnect回调，使用配置的副本调用它
	cfg := c.cfg
	if c.cfg.beforeConnect != nil {
		cfg = c.cfg.Clone()
		err = c.cfg.beforeConnect(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}

	// 创建新的mysqlConn实例
	mc := &mysqlConn{
		maxAllowedPacket: maxPacketSize,
		maxWriteSize:     maxPacketSize - 1,
		closech:          make(chan struct{}),
		cfg:              cfg,
		connector:        c,
	}
	mc.parseTime = mc.cfg.ParseTime

	// 连接到服务器
	dctx := ctx
	if mc.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
	}

	// 使用配置的DialFunc或默认的网络连接方法
	if c.cfg.DialFunc != nil {
		mc.netConn, err = c.cfg.DialFunc(dctx, mc.cfg.Net, mc.cfg.Addr)
	} else {
		dialsLock.RLock()
		dial, ok := dials[mc.cfg.Net]
		dialsLock.RUnlock()
		if ok {
			mc.netConn, err = dial(dctx, mc.cfg.Addr)
		} else {
			nd := net.Dialer{}
			mc.netConn, err = nd.DialContext(dctx, mc.cfg.Net, mc.cfg.Addr)
		}
	}
	if err != nil {
		return nil, err
	}
	mc.rawConn = mc.netConn

	// 对TCP连接启用TCP保活
	if tc, ok := mc.netConn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			c.cfg.Logger.Print(err)
		}
	}

	// 启动上下文监视器（从Go 1.8开始）
	mc.startWatcher()
	if err := mc.watchCancel(ctx); err != nil {
		mc.cleanup()
		return nil, err
	}
	defer mc.finish()

	// 初始化缓冲区
	mc.buf = newBuffer(mc.netConn)

	// 设置I/O超时
	mc.buf.timeout = mc.cfg.ReadTimeout
	mc.writeTimeout = mc.cfg.WriteTimeout

	// 读取握手初始化数据包
	authData, plugin, err := mc.readHandshakePacket()
	if err != nil {
		mc.cleanup()
		return nil, err
	}

	if plugin == "" {
		plugin = defaultAuthPlugin
	}

	// 发送客户端认证数据包
	authResp, err := mc.auth(authData, plugin)
	if err != nil {
		// 如果使用请求的插件失败，尝试默认认证插件
		c.cfg.Logger.Print("could not use requested auth plugin '"+plugin+"': ", err.Error())
		plugin = defaultAuthPlugin
		authResp, err = mc.auth(authData, plugin)
		if err != nil {
			mc.cleanup()
			return nil, err
		}
	}
	if err = mc.writeHandshakeResponsePacket(authResp, plugin); err != nil {
		mc.cleanup()
		return nil, err
	}

	// 处理认证结果
	if err = mc.handleAuthResult(authData, plugin); err != nil {
		// Authentication failed and MySQL has already closed the connection
		// (https://dev.mysql.com/doc/internals/en/authentication-fails.html).
		// Do not send COM_QUIT, just cleanup and return the error.
		// 认证失败，MySQL已经关闭连接
		// 不发送COM_QUIT，只清理并返回错误
		mc.cleanup()
		return nil, err
	}

	// 设置最大允许的数据包大小
	if mc.cfg.MaxAllowedPacket > 0 {
		mc.maxAllowedPacket = mc.cfg.MaxAllowedPacket
	} else {
		// 获取系统变量中的最大允许数据包大小
		maxap, err := mc.getSystemVar("max_allowed_packet")
		if err != nil {
			mc.Close()
			return nil, err
		}
		mc.maxAllowedPacket = stringToInt(maxap) - 1
	}
	if mc.maxAllowedPacket < maxPacketSize {
		mc.maxWriteSize = mc.maxAllowedPacket
	}

	// Charset: character_set_connection, character_set_client, character_set_results
	if len(mc.cfg.charsets) > 0 {
		for _, cs := range mc.cfg.charsets {
			// 忽略错误 - 字符集可能不存在
			if mc.cfg.Collation != "" {
				err = mc.exec("SET NAMES " + cs + " COLLATE " + mc.cfg.Collation)
			} else {
				err = mc.exec("SET NAMES " + cs)
			}
			if err == nil {
				break
			}
		}
		if err != nil {
			mc.Close()
			return nil, err
		}
	}

	// 处理DSN参数
	err = mc.handleParams()
	if err != nil {
		mc.Close()
		return nil, err
	}

	return mc, nil
}

// Driver 实现 driver.Connector 接口
// Driver 返回 &MySQLDriver{}
func (c *connector) Driver() driver.Driver {
	return &MySQLDriver{}
}
