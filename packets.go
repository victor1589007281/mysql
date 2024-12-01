// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"bytes"
	"crypto/tls"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
)

// MySQL client/server protocol documentations.
// https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
// https://mariadb.com/kb/en/clientserver-protocol/
// MySQL客户端/服务器协议文档

// Read packet to buffer 'data'
// 从连接读取数据包到缓冲区'data'
func (mc *mysqlConn) readPacket() ([]byte, error) {
	var prevData []byte
	for {
		// read packet header
		// 读取4字节的数据包头
		data, err := mc.buf.readNext(4)
		if err != nil {
			mc.close()
			if cerr := mc.canceled.Value(); cerr != nil {
				return nil, cerr
			}
			mc.log(err)
			return nil, ErrInvalidConn
		}

		// packet length [24 bit]
		// 数据包长度[24位]
		pktLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)

		// check packet sync [8 bit]
		// 检查数据包同步位[8位]
		if data[3] != mc.sequence {
			mc.close()
			if data[3] > mc.sequence {
				return nil, ErrPktSyncMul
			}
			return nil, ErrPktSync
		}
		mc.sequence++

		// packets with length 0 terminate a previous packet which is a
		// multiple of (2^24)-1 bytes long
		// 长度为0的数据包表示终止前一个(2^24)-1字节长的数据包
		if pktLen == 0 {
			// there was no previous packet
			// 如果没有前一个数据包
			if prevData == nil {
				mc.log(ErrMalformPkt)
				mc.close()
				return nil, ErrInvalidConn
			}

			return prevData, nil
		}

		// read packet body [pktLen bytes]
		// 读取数据包主体[pktLen字节]
		data, err = mc.buf.readNext(pktLen)
		if err != nil {
			mc.close()
			if cerr := mc.canceled.Value(); cerr != nil {
				return nil, cerr
			}
			mc.log(err)
			return nil, ErrInvalidConn
		}

		// return data if this was the last packet
		// 如果这是最后一个数据包则返回数据
		if pktLen < maxPacketSize {
			// zero allocations for non-split packets
			// 对于非分片数据包零分配
			if prevData == nil {
				return data, nil
			}

			return append(prevData, data...), nil
		}

		prevData = append(prevData, data...)
	}
}

// Write packet buffer 'data'
// 写入数据包缓冲区'data'
func (mc *mysqlConn) writePacket(data []byte) error {
	pktLen := len(data) - 4

	if pktLen > mc.maxAllowedPacket {
		return ErrPktTooLarge
	}

	for {
		var size int
		// 处理大数据包分片
		if pktLen >= maxPacketSize {
			data[0] = 0xff
			data[1] = 0xff
			data[2] = 0xff
			size = maxPacketSize
		} else {
			// 设置数据包长度(3字节)
			data[0] = byte(pktLen)
			data[1] = byte(pktLen >> 8)
			data[2] = byte(pktLen >> 16)
			size = pktLen
		}
		data[3] = mc.sequence

		// Write packet
		// 写入数据包
		if mc.writeTimeout > 0 {
			if err := mc.netConn.SetWriteDeadline(time.Now().Add(mc.writeTimeout)); err != nil {
				mc.cleanup()
				mc.log(err)
				return err
			}
		}

		// 写入数据包到网络连接
		n, err := mc.netConn.Write(data[:4+size])
		if err != nil {
			mc.cleanup()
			if cerr := mc.canceled.Value(); cerr != nil {
				return cerr
			}
			if n == 0 && pktLen == len(data)-4 {
				// only for the first loop iteration when nothing was written yet
				// 仅用于第一次循环迭代时还未写入任何数据的情况
				mc.log(err)
				return errBadConnNoWrite
			} else {
				return err
			}
		}
		if n != 4+size {
			// io.Writer(b) must return a non-nil error if it cannot write len(b) bytes.
			// The io.ErrShortWrite error is used to indicate that this rule has not been followed.
			// 如果无法写入指定长度的字节,io.Writer(b)必须返回非nil错误
			// io.ErrShortWrite错误用于指示未遵循此规则
			mc.cleanup()
			return io.ErrShortWrite
		}

		mc.sequence++
		if size != maxPacketSize {
			return nil
		}
		pktLen -= size
		data = data[size:]
	}
}

/******************************************************************************
*                           Initialization Process                             *
******************************************************************************/

// Handshake Initialization Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
// 握手初始化数据包
func (mc *mysqlConn) readHandshakePacket() (data []byte, plugin string, err error) {
	data, err = mc.readPacket()
	if err != nil {
		return
	}

	if data[0] == iERR {
		return nil, "", mc.handleErrorPacket(data)
	}

	// protocol version [1 byte]
	// 协议版本 [1字节]
	if data[0] < minProtocolVersion {
		return nil, "", fmt.Errorf(
			"unsupported protocol version %d. Version %d or higher is required",
			data[0],
			minProtocolVersion,
		)
	}

	// server version [null terminated string]
	// connection id [4 bytes]
	// 服务器版本[以null结尾的字符串]
	// 连接ID [4字节]
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	// first part of the password cipher [8 bytes]
	// 密码加密的第一部分 [8字节]
	authData := data[pos : pos+8]

	// (filler) always 0x00 [1 byte]
	// (填充字节) 始终为0x00 [1字节]
	pos += 8 + 1

	// capability flags (lower 2 bytes) [2 bytes]
	// 能力标志(低2字节) [2字节]
	mc.flags = clientFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
	if mc.flags&clientProtocol41 == 0 {
		return nil, "", ErrOldProtocol
	}
	if mc.flags&clientSSL == 0 && mc.cfg.TLS != nil {
		if mc.cfg.AllowFallbackToPlaintext {
			mc.cfg.TLS = nil
		} else {
			return nil, "", ErrNoTLS
		}
	}
	pos += 2

	if len(data) > pos {
		// character set [1 byte]
		// status flags [2 bytes]
		// 字符集 [1字节]
		// 状态标志 [2字节]
		pos += 3

		// capability flags (upper 2 bytes) [2 bytes]
		// 能力标志(高2字节) [2字节]
		mc.flags |= clientFlag(binary.LittleEndian.Uint16(data[pos:pos+2])) << 16
		pos += 2

		// length of auth-plugin-data [1 byte]
		// reserved (all [00]) [10 bytes]
		// 认证插件数据长度 [1字节]
		// 保留字段(全为[00]) [10字节]
		pos += 11

		// second part of the password cipher [minimum 13 bytes],
		// where len=MAX(13, length of auth-plugin-data - 8)
		//
		// The web documentation is ambiguous about the length. However,
		// according to mysql-5.7/sql/auth/sql_authentication.cc line 538,
		// the 13th byte is "\0 byte, terminating the second part of
		// a scramble". So the second part of the password cipher is
		// a NULL terminated string that's at least 13 bytes with the
		// last byte being NULL.
		//
		// The official Python library uses the fixed length 12
		// which seems to work but technically could have a hidden bug.
		// 密码加密的第二部分[最少13字节]
		// 其中长度=MAX(13, 认证插件数据长度 - 8)
		//
		// Web文档对长度的描述有歧义。但是根据mysql-5.7/sql/auth/sql_authentication.cc第538行,
		// 第13个字节是"\0字节,终止加密的第二部分"。所以密码加密第二部分是一个NULL结尾的字符串,
		// 至少13字节,最后一个字节是NULL。
		//
		// 官方Python库使用固定长度12,这似乎可以工作但从技术上讲可能存在隐藏的bug。
		authData = append(authData, data[pos:pos+12]...)
		pos += 13

		// EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
		// \NUL otherwise
		// 如果版本在(>= 5.5.7 且 < 5.5.10)或(>= 5.6.0 且 < 5.6.2)之间则为EOF
		// 否则为\NUL
		if end := bytes.IndexByte(data[pos:], 0x00); end != -1 {
			plugin = string(data[pos : pos+end])
		} else {
			plugin = string(data[pos:])
		}

		// make a memory safe copy of the cipher slice
		// 创建加密切片的内存安全副本
		var b [20]byte
		copy(b[:], authData)
		return b[:], plugin, nil
	}

	// make a memory safe copy of the cipher slice
	// 创建加密切片的内存安全副本
	var b [8]byte
	copy(b[:], authData)
	return b[:], plugin, nil
}

// Client Authentication Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
// 客户端认证数据包
func (mc *mysqlConn) writeHandshakeResponsePacket(authResp []byte, plugin string) error {
	// Adjust client flags based on server support
	// 根据服务器支持调整客户端标志
	clientFlags := clientProtocol41 |
		clientSecureConn |
		clientLongPassword |
		clientTransactions |
		clientLocalFiles |
		clientPluginAuth |
		clientMultiResults |
		mc.flags&clientConnectAttrs |
		mc.flags&clientLongFlag

	sendConnectAttrs := mc.flags&clientConnectAttrs != 0

	if mc.cfg.ClientFoundRows {
		clientFlags |= clientFoundRows
	}

	// To enable TLS / SSL
	// 启用 TLS / SSL
	if mc.cfg.TLS != nil {
		clientFlags |= clientSSL
	}

	if mc.cfg.MultiStatements {
		clientFlags |= clientMultiStatements
	}

	// encode length of the auth plugin data
	// 编码认证插件数据的长度
	var authRespLEIBuf [9]byte
	authRespLen := len(authResp)
	authRespLEI := appendLengthEncodedInteger(authRespLEIBuf[:0], uint64(authRespLen))
	if len(authRespLEI) > 1 {
		// if the length can not be written in 1 byte, it must be written as a
		// length encoded integer
		// 如果长度不能用1字节写入,必须作为长度编码整数写入
		clientFlags |= clientPluginAuthLenEncClientData
	}

	// Calculate packet length and get buffer with that size
	// 计算数据包长度并获取相应大小的缓冲区
	pktLen := 4 + 4 + 1 + 23 + len(mc.cfg.User) + 1 + len(authRespLEI) + len(authResp) + 21 + 1

	// To specify a db name
	// 指定数据库名称
	if n := len(mc.cfg.DBName); n > 0 {
		clientFlags |= clientConnectWithDB
		pktLen += n + 1
	}

	// encode length of the connection attributes
	// 编码连接属性的长度
	var connAttrsLEI []byte
	if sendConnectAttrs {
		var connAttrsLEIBuf [9]byte
		connAttrsLen := len(mc.connector.encodedAttributes)
		connAttrsLEI = appendLengthEncodedInteger(connAttrsLEIBuf[:0], uint64(connAttrsLen))
		pktLen += len(connAttrsLEI) + len(mc.connector.encodedAttributes)
	}

	// Calculate packet length and get buffer with that size
	// 计算数据包长度并获取相应大小的缓冲区
	data, err := mc.buf.takeBuffer(pktLen + 4)
	if err != nil {
		mc.cleanup()
		return err
	}

	// ClientFlags [32 bit]
	// 客户端标志 [32位]
	data[4] = byte(clientFlags)
	data[5] = byte(clientFlags >> 8)
	data[6] = byte(clientFlags >> 16)
	data[7] = byte(clientFlags >> 24)

	// MaxPacketSize [32 bit] (none)
	// 最大数据包大小 [32位] (无)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Collation ID [1 byte]
	// 字符集校对ID [1字节]
	data[12] = defaultCollationID
	if cname := mc.cfg.Collation; cname != "" {
		colID, ok := collations[cname]
		if ok {
			data[12] = colID
		} else if len(mc.cfg.charsets) > 0 {
			// When cfg.charset is set, the collation is set by `SET NAMES <charset> COLLATE <collation>`.
			// 当设置了cfg.charset时,字符集校对通过`SET NAMES <charset> COLLATE <collation>`设置
			return fmt.Errorf("unknown collation: %q", cname)
		}
	}

	// Filler [23 bytes] (all 0x00)
	// 填充字节 [23字节] (全为0x00)
	pos := 13
	for ; pos < 13+23; pos++ {
		data[pos] = 0
	}

	// SSL Connection Request Packet
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	// SSL连接请求数据包
	if mc.cfg.TLS != nil {
		// Send TLS / SSL request packet
		// 发送 TLS / SSL 请求数据包
		if err := mc.writePacket(data[:(4+4+1+23)+4]); err != nil {
			return err
		}

		// Switch to TLS
		// 切换到TLS
		tlsConn := tls.Client(mc.netConn, mc.cfg.TLS)
		if err := tlsConn.Handshake(); err != nil {
			if cerr := mc.canceled.Value(); cerr != nil {
				return cerr
			}
			return err
		}
		mc.netConn = tlsConn
		mc.buf.nc = tlsConn
	}

	// User [null terminated string]
	// 用户名 [以null结尾的字符串]
	if len(mc.cfg.User) > 0 {
		pos += copy(data[pos:], mc.cfg.User)
	}
	data[pos] = 0x00
	pos++

	// Auth Data [length encoded integer]
	// 认证数据 [长度编码整数]
	pos += copy(data[pos:], authRespLEI)
	pos += copy(data[pos:], authResp)

	// Databasename [null terminated string]
	// 数据库名称 [以null结尾的字符串]
	if len(mc.cfg.DBName) > 0 {
		pos += copy(data[pos:], mc.cfg.DBName)
		data[pos] = 0x00
		pos++
	}

	pos += copy(data[pos:], plugin)
	data[pos] = 0x00
	pos++

	// Connection Attributes
	// 连接属性
	if sendConnectAttrs {
		pos += copy(data[pos:], connAttrsLEI)
		pos += copy(data[pos:], []byte(mc.connector.encodedAttributes))
	}

	// Send Auth packet
	// 发送认证数据包
	return mc.writePacket(data[:pos])
}

// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
// 认证切换响应数据包
func (mc *mysqlConn) writeAuthSwitchPacket(authData []byte) error {
	pktLen := 4 + len(authData)
	data, err := mc.buf.takeBuffer(pktLen)
	if err != nil {
		mc.cleanup()
		return err
	}

	// Add the auth data [EOF]
	// 添加认证数据 [EOF]
	copy(data[4:], authData)
	return mc.writePacket(data)
}

/******************************************************************************
*                             Command Packets                                 *
******************************************************************************/

// writeCommandPacket 发送命令数据包
func (mc *mysqlConn) writeCommandPacket(command byte) error {
	// Reset Packet Sequence
	// 重置数据包序列
	mc.sequence = 0

	data, err := mc.buf.takeSmallBuffer(4 + 1)
	if err != nil {
		return err
	}

	// Add command byte
	// 添加命令字节
	data[4] = command

	// Send CMD packet
	// 发送命令数据包
	return mc.writePacket(data)
}

// writeCommandPacketStr 发送带字符串参数的命令数据包
func (mc *mysqlConn) writeCommandPacketStr(command byte, arg string) error {
	// Reset Packet Sequence
	// 重置数据包序列
	mc.sequence = 0

	pktLen := 1 + len(arg)
	data, err := mc.buf.takeBuffer(pktLen + 4)
	if err != nil {
		return err
	}

	// Add command byte
	// 添加命令字节
	data[4] = command

	// Add arg
	// 添加参数
	copy(data[5:], arg)

	// Send CMD packet
	// 发送命令数据包
	return mc.writePacket(data)
}

// writeCommandPacketUint32 发送带uint32参数的命令数据包
func (mc *mysqlConn) writeCommandPacketUint32(command byte, arg uint32) error {
	// Reset Packet Sequence
	// 重置数据包序列
	mc.sequence = 0

	data, err := mc.buf.takeSmallBuffer(4 + 1 + 4)
	if err != nil {
		return err
	}

	// Add command byte
	// 添加命令字节
	data[4] = command

	// Add arg [32 bit]
	// 添加参数 [32位]
	data[5] = byte(arg)
	data[6] = byte(arg >> 8)
	data[7] = byte(arg >> 16)
	data[8] = byte(arg >> 24)

	// Send CMD packet
	// 发送命令数据包
	return mc.writePacket(data)
}

/******************************************************************************
*                              Result Packets                                 *
******************************************************************************/

// readAuthResult 读取认证结果
func (mc *mysqlConn) readAuthResult() ([]byte, string, error) {
	data, err := mc.readPacket()
	if err != nil {
		return nil, "", err
	}

	// packet indicator
	// 数据包指示符
	switch data[0] {

	case iOK:
		// resultUnchanged, since auth happens before any queries or
		// commands have been executed.
		// 结果未变，因为认证发生在任何查询或命令执行之前。
		return nil, "", mc.resultUnchanged().handleOkPacket(data)

	case iAuthMoreData:
		return data[1:], "", err

	case iEOF:
		if len(data) == 1 {
			// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::OldAuthSwitchRequest
			// 旧认证切换请求
			return nil, "mysql_old_password", nil
		}
		pluginEndIndex := bytes.IndexByte(data, 0x00)
		if pluginEndIndex < 0 {
			return nil, "", ErrMalformPkt
		}
		plugin := string(data[1:pluginEndIndex])
		authData := data[pluginEndIndex+1:]
		return authData, plugin, nil

	default: // Error otherwise
		// 否则为错误
		return nil, "", mc.handleErrorPacket(data)
	}
}

// Returns error if Packet is not a 'Result OK'-Packet
// 如果数据包不是'结果OK'数据包，则返回错误
func (mc *okHandler) readResultOK() error {
	data, err := mc.conn().readPacket()
	if err != nil {
		return err
	}

	if data[0] == iOK {
		return mc.handleOkPacket(data)
	}
	return mc.conn().handleErrorPacket(data)
}

// Result Set Header Packet
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response.html
// 结果集头数据包
func (mc *okHandler) readResultSetHeaderPacket() (int, error) {
	// handleOkPacket replaces both values; other cases leave the values unchanged.
	// handleOkPacket替换两个值；其他情况保持值不变。
	mc.result.affectedRows = append(mc.result.affectedRows, 0)
	mc.result.insertIds = append(mc.result.insertIds, 0)

	data, err := mc.conn().readPacket()
	if err != nil {
		return 0, err
	}

	switch data[0] {
	case iOK:
		return 0, mc.handleOkPacket(data)

	case iERR:
		return 0, mc.conn().handleErrorPacket(data)

	case iLocalInFile:
		return 0, mc.handleInFileRequest(string(data[1:]))
	}

	// column count
	// 列数
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html
	num, _, _ := readLengthEncodedInteger(data)
	// ignore remaining data in the packet. see #1478.
	// 忽略数据包中的剩余数据。见#1478。
	return int(num), nil
}

// Error Packet
// http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-ERR_Packet
// 错误数据包
func (mc *mysqlConn) handleErrorPacket(data []byte) error {
	if data[0] != iERR {
		return ErrMalformPkt
	}

	// 0xff [1 byte]
	// 错误编号 [16位无符号整数]
	errno := binary.LittleEndian.Uint16(data[1:3])

	// 1792: ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
	// 1290: ER_OPTION_PREVENTS_STATEMENT (returned by Aurora during failover)
	// 1792: ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
	// 1290: ER_OPTION_PREVENTS_STATEMENT (在Aurora故障转移期间返回)
	if (errno == 1792 || errno == 1290) && mc.cfg.RejectReadOnly {
		// Oops; we are connected to a read-only connection, and won't be able
		// to issue any write statements. Since RejectReadOnly is configured,
		// we throw away this connection hoping this one would have write
		// permission. This is specifically for a possible race condition
		// during failover (e.g. on AWS Aurora). See README.md for more.
		//
		// We explicitly close the connection before returning
		// driver.ErrBadConn to ensure that `database/sql` purges this
		// connection and initiates a new one for next statement next time.
		// 哎呀；我们连接到一个只读连接，无法发出任何写入语句。由于配置了RejectReadOnly，
		// 我们丢弃此连接，希望此连接具有写入权限。这是专门针对故障转移期间可能的竞争条件
		// （例如在AWS Aurora上）。有关更多信息，请参阅README.md。
		//
		// 在返回driver.ErrBadConn之前，我们显式关闭连接，以确保`database/sql`清除此
		// 连接并在下次为下一个语句启动新连接。
		mc.Close()
		return driver.ErrBadConn
	}

	me := &MySQLError{Number: errno}

	pos := 3

	// SQL State [optional: # + 5bytes string]
	// SQL状态 [可选: # + 5字节字符串]
	if data[3] == 0x23 {
		copy(me.SQLState[:], data[4:4+5])
		pos = 9
	}

	// Error Message [string]
	// 错误消息 [字符串]
	me.Message = string(data[pos:])

	return me
}

// readStatus 读取状态标志
func readStatus(b []byte) statusFlag {
	return statusFlag(b[0]) | statusFlag(b[1])<<8
}

// Returns an instance of okHandler for codepaths where mysqlConn.result doesn't
// need to be cleared first (e.g. during authentication, or while additional
// resultsets are being fetched.)
// 返回okHandler的实例，用于mysqlConn.result不需要先清除的代码路径（例如，在身份验证期间，或在获取附加结果集时）。
func (mc *mysqlConn) resultUnchanged() *okHandler {
	return (*okHandler)(mc)
}

// okHandler represents the state of the connection when mysqlConn.result has
// been prepared for processing of OK packets.
// okHandler表示mysqlConn.result准备处理OK数据包时的连接状态。
//
// To correctly populate mysqlConn.result (updated by handleOkPacket()), all
// callpaths must either:
// 为了正确填充mysqlConn.result（由handleOkPacket()更新），所有调用路径必须：
//
// 1. first clear it using clearResult(), or
// 1. 首先使用clearResult()清除它，或
// 2. confirm that they don't need to (by calling resultUnchanged()).
// 2. 确认他们不需要（通过调用resultUnchanged()）。
//
// Both return an instance of type *okHandler.
// 两者都返回类型为*okHandler的实例。
type okHandler mysqlConn

// Exposes the underlying type's methods.
// 暴露底层类型的方法。
func (mc *okHandler) conn() *mysqlConn {
	return (*mysqlConn)(mc)
}

// clearResult clears the connection's stored affectedRows and insertIds
// fields.
// 清除连接存储的affectedRows和insertIds字段。
//
// It returns a handler that can process OK responses.
// 它返回一个可以处理OK响应的处理程序。
func (mc *mysqlConn) clearResult() *okHandler {
	mc.result = mysqlResult{}
	return (*okHandler)(mc)
}

// Ok Packet
// http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-OK_Packet
// OK数据包
func (mc *okHandler) handleOkPacket(data []byte) error {
	var n, m int
	var affectedRows, insertId uint64

	// 0x00 [1 byte]
	// 受影响的行数 [长度编码二进制]
	affectedRows, _, n = readLengthEncodedInteger(data[1:])

	// 插入ID [长度编码二进制]
	insertId, _, m = readLengthEncodedInteger(data[1+n:])

	// Update for the current statement result (only used by
	// readResultSetHeaderPacket).
	// 更新当前语句结果（仅由readResultSetHeaderPacket使用）。
	if len(mc.result.affectedRows) > 0 {
		mc.result.affectedRows[len(mc.result.affectedRows)-1] = int64(affectedRows)
	}
	if len(mc.result.insertIds) > 0 {
		mc.result.insertIds[len(mc.result.insertIds)-1] = int64(insertId)
	}

	// server_status [2 bytes]
	// 服务器状态 [2字节]
	mc.status = readStatus(data[1+n+m : 1+n+m+2])
	if mc.status&statusMoreResultsExists != 0 {
		return nil
	}

	// warning count [2 bytes]
	// 警告计数 [2字节]

	return nil
}

// Read Packets as Field Packets until EOF-Packet or an Error appears
// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
// 读取数据包作为字段数据包，直到EOF数据包或出现错误
func (mc *mysqlConn) readColumns(count int) ([]mysqlField, error) {
	columns := make([]mysqlField, count)

	for i := 0; ; i++ {
		data, err := mc.readPacket()
		if err != nil {
			return nil, err
		}

		// EOF Packet
		// EOF数据包
		if data[0] == iEOF && (len(data) == 5 || len(data) == 1) {
			if i == count {
				return columns, nil
			}
			return nil, fmt.Errorf("column count mismatch n:%d len:%d", count, len(columns))
		}

		// Catalog
		// 目录
		pos, err := skipLengthEncodedString(data)
		if err != nil {
			return nil, err
		}

		// Database [len coded string]
		// 数据库 [长度编码字符串]
		n, err := skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Table [len coded string]
		// 表 [长度编码字符串]
		if mc.cfg.ColumnsWithAlias {
			tableName, _, n, err := readLengthEncodedString(data[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			columns[i].tableName = string(tableName)
		} else {
			n, err = skipLengthEncodedString(data[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
		}

		// Original table [len coded string]
		// 原始表 [长度编码字符串]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Name [len coded string]
		// 名称 [长度编码字符串]
		name, _, n, err := readLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		columns[i].name = string(name)
		pos += n

		// Original name [len coded string]
		// 原始名称 [长度编码字符串]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Filler [uint8]
		// 填充字节 [uint8]
		pos++

		// Charset [charset, collation uint8]
		// 字符集 [字符集, 校对 uint8]
		columns[i].charSet = data[pos]
		pos += 2

		// Length [uint32]
		// 长度 [uint32]
		columns[i].length = binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4

		// Field type [uint8]
		// 字段类型 [uint8]
		columns[i].fieldType = fieldType(data[pos])
		pos++

		// Flags [uint16]
		// 标志 [uint16]
		columns[i].flags = fieldFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2

		// Decimals [uint8]
		// 小数位 [uint8]
		columns[i].decimals = data[pos]
		//pos++

		// Default value [len coded binary]
		// 默认值 [长度编码二进制]
		//if pos < len(data) {
		//	defaultVal, _, err = bytesToLengthCodedBinary(data[pos:])
		//}
	}
}

// Read Packets as Field Packets until EOF-Packet or an Error appears
// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow
// 读取数据包作为字段数据包，直到EOF数据包或出现错误
func (rows *textRows) readRow(dest []driver.Value) error {
	mc := rows.mc

	if rows.rs.done {
		return io.EOF
	}

	data, err := mc.readPacket()
	if err != nil {
		return err
	}

	// EOF Packet
	// EOF数据包
	if data[0] == iEOF && len(data) == 5 {
		// server_status [2 bytes]
		// 服务器状态 [2字节]
		rows.mc.status = readStatus(data[3:])
		rows.rs.done = true
		if !rows.HasNextResultSet() {
			rows.mc = nil
		}
		return io.EOF
	}
	if data[0] == iERR {
		rows.mc = nil
		return mc.handleErrorPacket(data)
	}

	// RowSet Packet
	// 行集数据包
	var (
		n      int
		isNull bool
		pos    int = 0
	)

	for i := range dest {
		// Read bytes and convert to string
		// 读取字节并转换为字符串
		var buf []byte
		buf, isNull, n, err = readLengthEncodedString(data[pos:])
		pos += n

		if err != nil {
			return err
		}

		if isNull {
			dest[i] = nil
			continue
		}

		switch rows.rs.columns[i].fieldType {
		case fieldTypeTimestamp,
			fieldTypeDateTime,
			fieldTypeDate,
			fieldTypeNewDate:
			if mc.parseTime {
				dest[i], err = parseDateTime(buf, mc.cfg.Loc)
			} else {
				dest[i] = buf
			}

		case fieldTypeTiny, fieldTypeShort, fieldTypeInt24, fieldTypeYear, fieldTypeLong:
			dest[i], err = strconv.ParseInt(string(buf), 10, 64)

		case fieldTypeLongLong:
			if rows.rs.columns[i].flags&flagUnsigned != 0 {
				dest[i], err = strconv.ParseUint(string(buf), 10, 64)
			} else {
				dest[i], err = strconv.ParseInt(string(buf), 10, 64)
			}

		case fieldTypeFloat:
			var d float64
			d, err = strconv.ParseFloat(string(buf), 32)
			dest[i] = float32(d)

		case fieldTypeDouble:
			dest[i], err = strconv.ParseFloat(string(buf), 64)

		default:
			dest[i] = buf
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// Reads Packets until EOF-Packet or an Error appears. Returns count of Packets read
// 读取数据包直到EOF数据包或出现错误。返回读取的数据包数量
func (mc *mysqlConn) readUntilEOF() error {
	for {
		data, err := mc.readPacket()
		if err != nil {
			return err
		}

		switch data[0] {
		case iERR:
			return mc.handleErrorPacket(data)
		case iEOF:
			if len(data) == 5 {
				mc.status = readStatus(data[3:])
			}
			return nil
		}
	}
}

/******************************************************************************
*                           Prepared Statements                               *
******************************************************************************/

// Prepare Result Packets
// http://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
// 准备结果数据包
func (stmt *mysqlStmt) readPrepareResultPacket() (uint16, error) {
	data, err := stmt.mc.readPacket()
	if err == nil {
		// packet indicator [1 byte]
		// 数据包指示符 [1字节]
		if data[0] != iOK {
			return 0, stmt.mc.handleErrorPacket(data)
		}

		// statement id [4 bytes]
		// 语句ID [4字节]
		stmt.id = binary.LittleEndian.Uint32(data[1:5])

		// Column count [16 bit uint]
		// 列数 [16位无符号整数]
		columnCount := binary.LittleEndian.Uint16(data[5:7])

		// Param count [16 bit uint]
		// 参数数 [16位无符号整数]
		stmt.paramCount = int(binary.LittleEndian.Uint16(data[7:9]))

		// Reserved [8 bit]
		// 保留 [8位]

		// Warning count [16 bit uint]
		// 警告计数 [16位无符号整数]

		return columnCount, nil
	}
	return 0, err
}

// http://dev.mysql.com/doc/internals/en/com-stmt-send-long-data.html
// 发送长数据命令
func (stmt *mysqlStmt) writeCommandLongData(paramID int, arg []byte) error {
	maxLen := stmt.mc.maxAllowedPacket - 1
	pktLen := maxLen

	// After the header (bytes 0-3) follows before the data:
	// 1 byte command
	// 4 bytes stmtID
	// 2 bytes paramID
	// 在数据之前的头部（字节0-3）之后：
	// 1字节命令
	// 4字节stmtID
	// 2字节paramID
	const dataOffset = 1 + 4 + 2

	// Cannot use the write buffer since
	// a) the buffer is too small
	// b) it is in use
	// 不能使用写缓冲区，因为
	// a) 缓冲区太小
	// b) 正在使用中
	data := make([]byte, 4+1+4+2+len(arg))

	copy(data[4+dataOffset:], arg)

	for argLen := len(arg); argLen > 0; argLen -= pktLen - dataOffset {
		if dataOffset+argLen < maxLen {
			pktLen = dataOffset + argLen
		}

		stmt.mc.sequence = 0
		// Add command byte [1 byte]
		// 添加命令字节 [1字节]
		data[4] = comStmtSendLongData

		// Add stmtID [32 bit]
		// 添加stmtID [32位]
		data[5] = byte(stmt.id)
		data[6] = byte(stmt.id >> 8)
		data[7] = byte(stmt.id >> 16)
		data[8] = byte(stmt.id >> 24)

		// Add paramID [16 bit]
		// 添加paramID [16位]
		data[9] = byte(paramID)
		data[10] = byte(paramID >> 8)

		// Send CMD packet
		// 发送命令数据包
		err := stmt.mc.writePacket(data[:4+pktLen])
		if err == nil {
			data = data[pktLen-dataOffset:]
			continue
		}
		return err

	}

	// Reset Packet Sequence
	// 重置数据包序列
	stmt.mc.sequence = 0
	return nil
}

// Execute Prepared Statement
// http://dev.mysql.com/doc/internals/en/com-stmt-execute.html
// 执行预处理语句
func (stmt *mysqlStmt) writeExecutePacket(args []driver.Value) error {
	if len(args) != stmt.paramCount {
		return fmt.Errorf(
			"argument count mismatch (got: %d; has: %d)",
			len(args),
			stmt.paramCount,
		)
	}

	const minPktLen = 4 + 1 + 4 + 1 + 4
	mc := stmt.mc

	// Determine threshold dynamically to avoid packet size shortage.
	// 动态确定阈值以避免数据包大小不足。
	longDataSize := mc.maxAllowedPacket / (stmt.paramCount + 1)
	if longDataSize < 64 {
		longDataSize = 64
	}

	// Reset packet-sequence
	// 重置数据包序列
	mc.sequence = 0

	var data []byte
	var err error

	if len(args) == 0 {
		data, err = mc.buf.takeBuffer(minPktLen)
	} else {
		data, err = mc.buf.takeCompleteBuffer()
		// In this case the len(data) == cap(data) which is used to optimise the flow below.
		// 在这种情况下，len(data) == cap(data)，用于优化下面的流程。
	}
	if err != nil {
		return err
	}

	// command [1 byte]
	// 命令 [1字节]
	data[4] = comStmtExecute

	// statement_id [4 bytes]
	// 语句ID [4字节]
	data[5] = byte(stmt.id)
	data[6] = byte(stmt.id >> 8)
	data[7] = byte(stmt.id >> 16)
	data[8] = byte(stmt.id >> 24)

	// flags (0: CURSOR_TYPE_NO_CURSOR) [1 byte]
	// 标志 (0: CURSOR_TYPE_NO_CURSOR) [1字节]
	data[9] = 0x00

	// iteration_count (uint32(1)) [4 bytes]
	// 迭代计数 (uint32(1)) [4字节]
	data[10] = 0x01
	data[11] = 0x00
	data[12] = 0x00
	data[13] = 0x00

	if len(args) > 0 {
		pos := minPktLen

		var nullMask []byte
		if maskLen, typesLen := (len(args)+7)/8, 1+2*len(args); pos+maskLen+typesLen >= cap(data) {
			// buffer has to be extended but we don't know by how much so
			// we depend on append after all data with known sizes fit.
			// We stop at that because we deal with a lot of columns here
			// which makes the required allocation size hard to guess.
			// 缓冲区必须扩展，但我们不知道扩展多少，因此
			// 在所有已知大小的数据适合后依赖于append。
			// 我们在此停止，因为我们在这里处理很多列
			// 这使得所需的分配大小难以猜测。
			tmp := make([]byte, pos+maskLen+typesLen)
			copy(tmp[:pos], data[:pos])
			data = tmp
			nullMask = data[pos : pos+maskLen]
			// No need to clean nullMask as make ensures that.
			// 不需要清理nullMask，因为make确保了这一点。
			pos += maskLen
		} else {
			nullMask = data[pos : pos+maskLen]
			for i := range nullMask {
				nullMask[i] = 0
			}
			pos += maskLen
		}

		// newParameterBoundFlag 1 [1 byte]
		// 新参数绑定标志 1 [1字节]
		data[pos] = 0x01
		pos++

		// type of each parameter [len(args)*2 bytes]
		// 每个参数的类型 [len(args)*2字节]
		paramTypes := data[pos:]
		pos += len(args) * 2

		// value of each parameter [n bytes]
		// 每个参数的值 [n字节]
		paramValues := data[pos:pos]
		valuesCap := cap(paramValues)

		for i, arg := range args {
			// build NULL-bitmap
			// 构建NULL位图
			if arg == nil {
				nullMask[i/8] |= 1 << (uint(i) & 7)
				paramTypes[i+i] = byte(fieldTypeNULL)
				paramTypes[i+i+1] = 0x00
				continue
			}

			if v, ok := arg.(json.RawMessage); ok {
				arg = []byte(v)
			}
			// cache types and values
			// 缓存类型和值
			switch v := arg.(type) {
			case int64:
				paramTypes[i+i] = byte(fieldTypeLongLong)
				paramTypes[i+i+1] = 0x00

				if cap(paramValues)-len(paramValues)-8 >= 0 {
					paramValues = paramValues[:len(paramValues)+8]
					binary.LittleEndian.PutUint64(
						paramValues[len(paramValues)-8:],
						uint64(v),
					)
				} else {
					paramValues = append(paramValues,
						uint64ToBytes(uint64(v))...,
					)
				}

			case uint64:
				paramTypes[i+i] = byte(fieldTypeLongLong)
				paramTypes[i+i+1] = 0x80 // type is unsigned

				if cap(paramValues)-len(paramValues)-8 >= 0 {
					paramValues = paramValues[:len(paramValues)+8]
					binary.LittleEndian.PutUint64(
						paramValues[len(paramValues)-8:],
						uint64(v),
					)
				} else {
					paramValues = append(paramValues,
						uint64ToBytes(uint64(v))...,
					)
				}

			case float64:
				paramTypes[i+i] = byte(fieldTypeDouble)
				paramTypes[i+i+1] = 0x00

				if cap(paramValues)-len(paramValues)-8 >= 0 {
					paramValues = paramValues[:len(paramValues)+8]
					binary.LittleEndian.PutUint64(
						paramValues[len(paramValues)-8:],
						math.Float64bits(v),
					)
				} else {
					paramValues = append(paramValues,
						uint64ToBytes(math.Float64bits(v))...,
					)
				}

			case bool:
				paramTypes[i+i] = byte(fieldTypeTiny)
				paramTypes[i+i+1] = 0x00

				if v {
					paramValues = append(paramValues, 0x01)
				} else {
					paramValues = append(paramValues, 0x00)
				}

			case []byte:
				// Common case (non-nil value) first
				// 常见情况（非nil值）优先
				if v != nil {
					paramTypes[i+i] = byte(fieldTypeString)
					paramTypes[i+i+1] = 0x00

					if len(v) < longDataSize {
						paramValues = appendLengthEncodedInteger(paramValues,
							uint64(len(v)),
						)
						paramValues = append(paramValues, v...)
					} else {
						if err := stmt.writeCommandLongData(i, v); err != nil {
							return err
						}
					}
					continue
				}

				// Handle []byte(nil) as a NULL value
				// 将[]byte(nil)处理为NULL值
				nullMask[i/8] |= 1 << (uint(i) & 7)
				paramTypes[i+i] = byte(fieldTypeNULL)
				paramTypes[i+i+1] = 0x00

			case string:
				paramTypes[i+i] = byte(fieldTypeString)
				paramTypes[i+i+1] = 0x00

				if len(v) < longDataSize {
					paramValues = appendLengthEncodedInteger(paramValues,
						uint64(len(v)),
					)
					paramValues = append(paramValues, v...)
				} else {
					if err := stmt.writeCommandLongData(i, []byte(v)); err != nil {
						return err
					}
				}

			case time.Time:
				paramTypes[i+i] = byte(fieldTypeString)
				paramTypes[i+i+1] = 0x00

				var a [64]byte
				var b = a[:0]

				if v.IsZero() {
					b = append(b, "0000-00-00"...)
				} else {
					b, err = appendDateTime(b, v.In(mc.cfg.Loc), mc.cfg.timeTruncate)
					if err != nil {
						return err
					}
				}

				paramValues = appendLengthEncodedInteger(paramValues,
					uint64(len(b)),
				)
				paramValues = append(paramValues, b...)

			default:
				return fmt.Errorf("cannot convert type: %T", arg)
			}
		}

		// Check if param values exceeded the available buffer
		// In that case we must build the data packet with the new values buffer
		// 检查参数值是否超出可用缓冲区
		// 在这种情况下，我们必须使用新值缓冲区构建数据包
		if valuesCap != cap(paramValues) {
			data = append(data[:pos], paramValues...)
			if err = mc.buf.store(data); err != nil {
				return err
			}
		}

		pos += len(paramValues)
		data = data[:pos]
	}

	return mc.writePacket(data)
}

// For each remaining resultset in the stream, discards its rows and updates
// mc.affectedRows and mc.insertIds.
// 对于流中的每个剩余结果集，丢弃其行并更新mc.affectedRows和mc.insertIds。
func (mc *okHandler) discardResults() error {
	for mc.status&statusMoreResultsExists != 0 {
		resLen, err := mc.readResultSetHeaderPacket()
		if err != nil {
			return err
		}
		if resLen > 0 {
			// columns
			// 列
			if err := mc.conn().readUntilEOF(); err != nil {
				return err
			}
			// rows
			// 行
			if err := mc.conn().readUntilEOF(); err != nil {
				return err
			}
		}
	}
	return nil
}

// http://dev.mysql.com/doc/internals/en/binary-protocol-resultset-row.html
// 二进制协议结果集行
func (rows *binaryRows) readRow(dest []driver.Value) error {
	data, err := rows.mc.readPacket()
	if err != nil {
		return err
	}

	// packet indicator [1 byte]
	// 数据包指示符 [1字节]
	if data[0] != iOK {
		// EOF Packet
		// EOF数据包
		if data[0] == iEOF && len(data) == 5 {
			rows.mc.status = readStatus(data[3:])
			rows.rs.done = true
			if !rows.HasNextResultSet() {
				rows.mc = nil
			}
			return io.EOF
		}
		mc := rows.mc
		rows.mc = nil

		// Error otherwise
		// 否则为错误
		return mc.handleErrorPacket(data)
	}

	// NULL-bitmap,  [(column-count + 7 + 2) / 8 bytes]
	// NULL位图,  [(列数 + 7 + 2) / 8字节]
	pos := 1 + (len(dest)+7+2)>>3
	nullMask := data[1:pos]

	for i := range dest {
		// Field is NULL
		// (byte >> bit-pos) % 2 == 1
		// 字段为NULL
		// (字节 >> 位位置) % 2 == 1
		if ((nullMask[(i+2)>>3] >> uint((i+2)&7)) & 1) == 1 {
			dest[i] = nil
			continue
		}

		// Convert to byte-coded string
		// 转换为字节编码字符串
		switch rows.rs.columns[i].fieldType {
		case fieldTypeNULL:
			dest[i] = nil
			continue

		// Numeric Types
		// 数字类型
		case fieldTypeTiny:
			if rows.rs.columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(data[pos])
			} else {
				dest[i] = int64(int8(data[pos]))
			}
			pos++
			continue

		case fieldTypeShort, fieldTypeYear:
			if rows.rs.columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(binary.LittleEndian.Uint16(data[pos : pos+2]))
			} else {
				dest[i] = int64(int16(binary.LittleEndian.Uint16(data[pos : pos+2])))
			}
			pos += 2
			continue

		case fieldTypeInt24, fieldTypeLong:
			if rows.rs.columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(binary.LittleEndian.Uint32(data[pos : pos+4]))
			} else {
				dest[i] = int64(int32(binary.LittleEndian.Uint32(data[pos : pos+4])))
			}
			pos += 4
			continue

		case fieldTypeLongLong:
			if rows.rs.columns[i].flags&flagUnsigned != 0 {
				val := binary.LittleEndian.Uint64(data[pos : pos+8])
				if val > math.MaxInt64 {
					dest[i] = uint64ToString(val)
				} else {
					dest[i] = int64(val)
				}
			} else {
				dest[i] = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
			}
			pos += 8
			continue

		case fieldTypeFloat:
			dest[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
			continue

		case fieldTypeDouble:
			dest[i] = math.Float64frombits(binary.LittleEndian.Uint64(data[pos : pos+8]))
			pos += 8
			continue

		// Length coded Binary Strings
		// 长度编码二进制字符串
		case fieldTypeDecimal, fieldTypeNewDecimal, fieldTypeVarChar,
			fieldTypeBit, fieldTypeEnum, fieldTypeSet, fieldTypeTinyBLOB,
			fieldTypeMediumBLOB, fieldTypeLongBLOB, fieldTypeBLOB,
			fieldTypeVarString, fieldTypeString, fieldTypeGeometry, fieldTypeJSON,
			fieldTypeVector:
			var isNull bool
			var n int
			dest[i], isNull, n, err = readLengthEncodedString(data[pos:])
			pos += n
			if err == nil {
				if !isNull {
					continue
				} else {
					dest[i] = nil
					continue
				}
			}
			return err

		case
			fieldTypeDate, fieldTypeNewDate, // Date YYYY-MM-DD
			fieldTypeTime,                         // Time [-][H]HH:MM:SS[.fractal]
			fieldTypeTimestamp, fieldTypeDateTime: // Timestamp YYYY-MM-DD HH:MM:SS[.fractal]

			num, isNull, n := readLengthEncodedInteger(data[pos:])
			pos += n

			switch {
			case isNull:
				dest[i] = nil
				continue
			case rows.rs.columns[i].fieldType == fieldTypeTime:
				// database/sql does not support an equivalent to TIME, return a string
				// database/sql不支持与TIME等效的内容，返回字符串
				var dstlen uint8
				switch decimals := rows.rs.columns[i].decimals; decimals {
				case 0x00, 0x1f:
					dstlen = 8
				case 1, 2, 3, 4, 5, 6:
					dstlen = 8 + 1 + decimals
				default:
					return fmt.Errorf(
						"protocol error, illegal decimals value %d",
						rows.rs.columns[i].decimals,
					)
				}
				dest[i], err = formatBinaryTime(data[pos:pos+int(num)], dstlen)
			case rows.mc.parseTime:
				dest[i], err = parseBinaryDateTime(num, data[pos:], rows.mc.cfg.Loc)
			default:
				var dstlen uint8
				if rows.rs.columns[i].fieldType == fieldTypeDate {
					dstlen = 10
				} else {
					switch decimals := rows.rs.columns[i].decimals; decimals {
					case 0x00, 0x1f:
						dstlen = 19
					case 1, 2, 3, 4, 5, 6:
						dstlen = 19 + 1 + decimals
					default:
						return fmt.Errorf(
							"protocol error, illegal decimals value %d",
							rows.rs.columns[i].decimals,
						)
					}
				}
				dest[i], err = formatBinaryDateTime(data[pos:pos+int(num)], dstlen)
			}

			if err == nil {
				pos += int(num)
				continue
			} else {
				return err
			}

		// Please report if this happens!
		// 如果发生这种情况，请报告！
		default:
			return fmt.Errorf("unknown field type %d", rows.rs.columns[i].fieldType)
		}
	}

	return nil
}
