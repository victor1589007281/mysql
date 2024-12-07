// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// mysqlConn表示与MySQL服务器的连接。
type mysqlConn struct {
	// 用于网络读写的缓冲区
	buf buffer
	// 当前网络连接
	netConn net.Conn
	// TLS连接时的底层连接
	rawConn net.Conn // underlying connection when netConn is TLS connection.
	// 查询结果，由clearResult()和handleOkPacket()管理
	result mysqlResult // managed by clearResult() and handleOkPacket().
	// MySQL连接配置
	cfg *Config
	// 数据库连接器
	connector *connector
	// MySQL服务器允许的最大数据包大小
	maxAllowedPacket int
	// 单次写入的最大数据大小
	maxWriteSize int
	// 写入超时时间
	writeTimeout time.Duration
	// 客户端标志位
	flags clientFlag
	// 服务器状态标志位
	status statusFlag
	// MySQL协议序列号
	sequence uint8
	// 是否自动解析时间类型
	parseTime bool

	// 以下字段用于上下文支持 (Go 1.8+)
	// 是否正在监视上下文
	watching bool
	// 用于发送上下文的通道
	watcher chan<- context.Context
	// 连接关闭信号通道
	closech chan struct{}
	// 查询完成信号通道
	finished chan<- struct{}
	// 连接取消时的错误信息，非nil表示连接已取消
	canceled atomicError // set non-nil if conn is canceled
	// 连接是否已关闭的标志，在closech关闭前设置
	closed atomic.Bool // set when conn is closed, before closech is closed
}

// Helper function to call per-connection logger.
// 辅助函数调用每个连接的日志记录器。
func (mc *mysqlConn) log(v ...any) {
	_, filename, lineno, ok := runtime.Caller(1)
	if ok {
		pos := strings.LastIndexByte(filename, '/')
		if pos != -1 {
			filename = filename[pos+1:]
		}
		prefix := fmt.Sprintf("%s:%d ", filename, lineno)
		v = append([]any{prefix}, v...)
	}

	mc.cfg.Logger.Print(v...)
}

// Handles parameters set in DSN after the connection is established
// 处理在连接建立后在DSN中设置的参数
func (mc *mysqlConn) handleParams() (err error) {
	var cmdSet strings.Builder

	for param, val := range mc.cfg.Params {
		if cmdSet.Len() == 0 {
			// Heuristic: 29 chars for each other key=value to reduce reallocations
			// 启发式：每个其他键=值29个字符以减少重新分配
			cmdSet.Grow(4 + len(param) + 3 + len(val) + 30*(len(mc.cfg.Params)-1))
			cmdSet.WriteString("SET ")
		} else {
			cmdSet.WriteString(", ")
		}
		cmdSet.WriteString(param)
		cmdSet.WriteString(" = ")
		cmdSet.WriteString(val)
	}

	if cmdSet.Len() > 0 {
		err = mc.exec(cmdSet.String())
	}

	return
}

// markBadConn replaces errBadConnNoWrite with driver.ErrBadConn.
// This function is used to return driver.ErrBadConn only when safe to retry.
// markBadConn将errBadConnNoWrite替换为driver.ErrBadConn。
// 此函数仅在安全重试时用于返回driver.ErrBadConn。
func (mc *mysqlConn) markBadConn(err error) error {
	if err == errBadConnNoWrite {
		return driver.ErrBadConn
	}
	return err
}

func (mc *mysqlConn) Begin() (driver.Tx, error) {
	return mc.begin(false)
}

func (mc *mysqlConn) begin(readOnly bool) (driver.Tx, error) {
	if mc.closed.Load() {
		return nil, driver.ErrBadConn
	}
	var q string
	if readOnly {
		q = "START TRANSACTION READ ONLY"
	} else {
		q = "START TRANSACTION"
	}
	err := mc.exec(q)
	if err == nil {
		return &mysqlTx{mc}, err
	}
	return nil, mc.markBadConn(err)
}

func (mc *mysqlConn) Close() (err error) {
	// Makes Close idempotent
	// 使Close幂等
	if !mc.closed.Load() {
		err = mc.writeCommandPacket(comQuit)
	}
	mc.close()
	return
}

// close closes the network connection and clear results without sending COM_QUIT.
// close关闭网络连接并清除结果而不发送COM_QUIT。
func (mc *mysqlConn) close() {
	mc.cleanup()
	mc.clearResult()
}

// Closes the network connection and unsets internal variables. Do not call this
// function after successfully authentication, call Close instead. This function
// is called before auth or on auth failure because MySQL will have already
// closed the network connection.
// 关闭网络连接并取消设置内部变量。成功认证后不要调用此函数，而是调用Close。
// 此函数在认证之前或认证失败时调用，因为MySQL将已经关闭网络连接。
func (mc *mysqlConn) cleanup() {
	if mc.closed.Swap(true) {
		return
	}

	// Makes cleanup idempotent
	// 使cleanup幂等
	close(mc.closech)
	conn := mc.rawConn
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		mc.log(err)
	}
	// This function can be called from multiple goroutines.
	// So we can not mc.clearResult() here.
	// Caller should do it if they are in safe goroutine.
	// 此函数可以从多个goroutine调用。
	// 因此我们不能在此处调用mc.clearResult()。
	// 如果调用者在安全的goroutine中，他们应该这样做。
}

func (mc *mysqlConn) error() error {
	if mc.closed.Load() {
		if err := mc.canceled.Value(); err != nil {
			return err
		}
		return ErrInvalidConn
	}
	return nil
}

func (mc *mysqlConn) Prepare(query string) (driver.Stmt, error) {
	if mc.closed.Load() {
		return nil, driver.ErrBadConn
	}
	// Send command
	// 发送命令
	err := mc.writeCommandPacketStr(comStmtPrepare, query)
	if err != nil {
		// STMT_PREPARE is safe to retry.  So we can return ErrBadConn here.
		// STMT_PREPARE可以安全重试。因此我们可以在此返回ErrBadConn。
		mc.log(err)
		return nil, driver.ErrBadConn
	}

	stmt := &mysqlStmt{
		mc: mc,
	}

	// Read Result
	// 读取结果
	columnCount, err := stmt.readPrepareResultPacket()
	if err == nil {
		if stmt.paramCount > 0 {
			if err = mc.readUntilEOF(); err != nil {
				return nil, err
			}
		}

		if columnCount > 0 {
			err = mc.readUntilEOF()
		}
	}

	return stmt, err
}

func (mc *mysqlConn) interpolateParams(query string, args []driver.Value) (string, error) {
	// Number of ? should be same to len(args)
	// ?的数量应与len(args)相同
	if strings.Count(query, "?") != len(args) {
		return "", driver.ErrSkip
	}

	buf, err := mc.buf.takeCompleteBuffer()
	if err != nil {
		// can not take the buffer. Something must be wrong with the connection
		// 无法获取缓冲区。连接一定有问题
		mc.cleanup()
		// interpolateParams would be called before sending any query.
		// So its safe to retry.
		// interpolateParams将在发送任何查询之前调用。
		// 因此可以安全重试。
		return "", driver.ErrBadConn
	}
	buf = buf[:0]
	argPos := 0

	for i := 0; i < len(query); i++ {
		q := strings.IndexByte(query[i:], '?')
		if q == -1 {
			buf = append(buf, query[i:]...)
			break
		}
		buf = append(buf, query[i:i+q]...)
		i += q

		arg := args[argPos]
		argPos++

		if arg == nil {
			buf = append(buf, "NULL"...)
			continue
		}

		switch v := arg.(type) {
		case int64:
			buf = strconv.AppendInt(buf, v, 10)
		case uint64:
			// Handle uint64 explicitly because our custom ConvertValue emits unsigned values
			// 显式处理uint64，因为我们的自定义ConvertValue会发出无符号值
			buf = strconv.AppendUint(buf, v, 10)
		case float64:
			buf = strconv.AppendFloat(buf, v, 'g', -1, 64)
		case bool:
			if v {
				buf = append(buf, '1')
			} else {
				buf = append(buf, '0')
			}
		case time.Time:
			if v.IsZero() {
				buf = append(buf, "'0000-00-00'"...)
			} else {
				buf = append(buf, '\'')
				buf, err = appendDateTime(buf, v.In(mc.cfg.Loc), mc.cfg.timeTruncate)
				if err != nil {
					return "", err
				}
				buf = append(buf, '\'')
			}
		case json.RawMessage:
			buf = append(buf, '\'')
			if mc.status&statusNoBackslashEscapes == 0 {
				buf = escapeBytesBackslash(buf, v)
			} else {
				buf = escapeBytesQuotes(buf, v)
			}
			buf = append(buf, '\'')
		case []byte:
			if v == nil {
				buf = append(buf, "NULL"...)
			} else {
				buf = append(buf, "_binary'"...)
				if mc.status&statusNoBackslashEscapes == 0 {
					buf = escapeBytesBackslash(buf, v)
				} else {
					buf = escapeBytesQuotes(buf, v)
				}
				buf = append(buf, '\'')
			}
		case string:
			buf = append(buf, '\'')
			if mc.status&statusNoBackslashEscapes == 0 {
				buf = escapeStringBackslash(buf, v)
			} else {
				buf = escapeStringQuotes(buf, v)
			}
			buf = append(buf, '\'')
		default:
			return "", driver.ErrSkip
		}

		if len(buf)+4 > mc.maxAllowedPacket {
			return "", driver.ErrSkip
		}
	}
	if argPos != len(args) {
		return "", driver.ErrSkip
	}
	return string(buf), nil
}

func (mc *mysqlConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	if mc.closed.Load() {
		return nil, driver.ErrBadConn
	}
	if len(args) != 0 {
		if !mc.cfg.InterpolateParams {
			return nil, driver.ErrSkip
		}
		// try to interpolate the parameters to save extra roundtrips for preparing and closing a statement
		// 尝试插值参数以节省准备和关闭语句的额外往返
		prepared, err := mc.interpolateParams(query, args)
		if err != nil {
			return nil, err
		}
		query = prepared
	}

	err := mc.exec(query)
	if err == nil {
		copied := mc.result
		return &copied, err
	}
	return nil, mc.markBadConn(err)
}

// Internal function to execute commands
// 执行命令的内部函数
func (mc *mysqlConn) exec(query string) error {
	handleOk := mc.clearResult()
	// Send command
	// 发送命令
	if err := mc.writeCommandPacketStr(comQuery, query); err != nil {
		return mc.markBadConn(err)
	}

	// Read Result
	// 读取结果
	resLen, err := handleOk.readResultSetHeaderPacket()
	if err != nil {
		return err
	}

	if resLen > 0 {
		// columns
		// 列
		if err := mc.readUntilEOF(); err != nil {
			return err
		}

		// rows
		// 行
		if err := mc.readUntilEOF(); err != nil {
			return err
		}
	}

	return handleOk.discardResults()
}

func (mc *mysqlConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	return mc.query(query, args)
}

func (mc *mysqlConn) query(query string, args []driver.Value) (*textRows, error) {
	handleOk := mc.clearResult()

	if mc.closed.Load() {
		return nil, driver.ErrBadConn
	}
	if len(args) != 0 {
		if !mc.cfg.InterpolateParams {
			return nil, driver.ErrSkip
		}
		// try client-side prepare to reduce roundtrip
		// 尝试客户端准备以减少往返
		prepared, err := mc.interpolateParams(query, args)
		if err != nil {
			return nil, err
		}
		query = prepared
	}
	// Send command
	// 发送命令
	err := mc.writeCommandPacketStr(comQuery, query)
	if err != nil {
		return nil, mc.markBadConn(err)
	}

	// Read Result
	// 读取结果
	var resLen int
	resLen, err = handleOk.readResultSetHeaderPacket()
	if err != nil {
		return nil, err
	}

	rows := new(textRows)
	rows.mc = mc

	if resLen == 0 {
		rows.rs.done = true

		switch err := rows.NextResultSet(); err {
		case nil, io.EOF:
			return rows, nil
		default:
			return nil, err
		}
	}

	// Columns
	// 列
	rows.rs.columns, err = mc.readColumns(resLen)
	return rows, err
}

// Gets the value of the given MySQL System Variable
// The returned byte slice is only valid until the next read
// 获取给定MySQL系统变量的值
// 返回的字节切片仅在下次读取之前有效
func (mc *mysqlConn) getSystemVar(name string) ([]byte, error) {
	// Send command
	// 发送命令
	handleOk := mc.clearResult()
	if err := mc.writeCommandPacketStr(comQuery, "SELECT @@"+name); err != nil {
		return nil, err
	}

	// Read Result
	// 读取结果
	resLen, err := handleOk.readResultSetHeaderPacket()
	if err == nil {
		rows := new(textRows)
		rows.mc = mc
		rows.rs.columns = []mysqlField{{fieldType: fieldTypeVarChar}}

		if resLen > 0 {
			// Columns
			// 列
			if err := mc.readUntilEOF(); err != nil {
				return nil, err
			}
		}

		dest := make([]driver.Value, resLen)
		if err = rows.readRow(dest); err == nil {
			return dest[0].([]byte), mc.readUntilEOF()
		}
	}
	return nil, err
}

// finish is called when the query has canceled.
// 当查询被取消时调用finish。
func (mc *mysqlConn) cancel(err error) {
	mc.canceled.Set(err)
	mc.cleanup()
}

// finish is called when the query has succeeded.
// 当查询成功时调用finish。
func (mc *mysqlConn) finish() {
	if !mc.watching || mc.finished == nil {
		return
	}
	select {
	case mc.finished <- struct{}{}:
		mc.watching = false
	case <-mc.closech:
	}
}

// Ping implements driver.Pinger interface
// Ping实现了driver.Pinger接口
func (mc *mysqlConn) Ping(ctx context.Context) (err error) {
	if mc.closed.Load() {
		return driver.ErrBadConn
	}

	if err = mc.watchCancel(ctx); err != nil {
		return
	}
	defer mc.finish()

	handleOk := mc.clearResult()
	if err = mc.writeCommandPacket(comPing); err != nil {
		return mc.markBadConn(err)
	}

	return handleOk.readResultOK()
}

// BeginTx implements driver.ConnBeginTx interface
// BeginTx实现了driver.ConnBeginTx接口
func (mc *mysqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if mc.closed.Load() {
		return nil, driver.ErrBadConn
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer mc.finish()

	if sql.IsolationLevel(opts.Isolation) != sql.LevelDefault {
		level, err := mapIsolationLevel(opts.Isolation)
		if err != nil {
			return nil, err
		}
		err = mc.exec("SET TRANSACTION ISOLATION LEVEL " + level)
		if err != nil {
			return nil, err
		}
	}

	return mc.begin(opts.ReadOnly)
}

func (mc *mysqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	rows, err := mc.query(query, dargs)
	if err != nil {
		mc.finish()
		return nil, err
	}
	rows.finish = mc.finish
	return rows, err
}

func (mc *mysqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer mc.finish()

	return mc.Exec(query, dargs)
}

func (mc *mysqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	stmt, err := mc.Prepare(query)
	mc.finish()
	if err != nil {
		return nil, err
	}

	select {
	default:
	case <-ctx.Done():
		stmt.Close()
		return nil, ctx.Err()
	}
	return stmt, nil
}

func (stmt *mysqlStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := stmt.mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	rows, err := stmt.query(dargs)
	if err != nil {
		stmt.mc.finish()
		return nil, err
	}
	rows.finish = stmt.mc.finish
	return rows, err
}

func (stmt *mysqlStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := stmt.mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer stmt.mc.finish()

	return stmt.Exec(dargs)
}

func (mc *mysqlConn) watchCancel(ctx context.Context) error {
	if mc.watching {
		// Reach here if canceled,
		// so the connection is already invalid
		// 如果取消，则到达此处，
		// 因此连接已经无效
		mc.cleanup()
		return nil
	}
	// When ctx is already cancelled, don't watch it.
	// 当ctx已取消时，不要监视它。
	if err := ctx.Err(); err != nil {
		return err
	}
	// When ctx is not cancellable, don't watch it.
	// 当ctx不可取消时，不要监视它。
	if ctx.Done() == nil {
		return nil
	}
	// When watcher is not alive, can't watch it.
	// 当监视器不活跃时，无法监视它。
	if mc.watcher == nil {
		return nil
	}

	mc.watching = true
	mc.watcher <- ctx
	return nil
}

func (mc *mysqlConn) startWatcher() {
	watcher := make(chan context.Context, 1)
	mc.watcher = watcher
	finished := make(chan struct{})
	mc.finished = finished
	go func() {
		for {
			var ctx context.Context
			select {
			case ctx = <-watcher:
			case <-mc.closech:
				return
			}

			select {
			case <-ctx.Done():
				mc.cancel(ctx.Err())
			case <-finished:
			case <-mc.closech:
				return
			}
		}
	}()
}

func (mc *mysqlConn) CheckNamedValue(nv *driver.NamedValue) (err error) {
	nv.Value, err = converter{}.ConvertValue(nv.Value)
	return
}

// ResetSession implements driver.SessionResetter.
// (From Go 1.10)
// ResetSession实现了driver.SessionResetter。
// (来自Go 1.10)
func (mc *mysqlConn) ResetSession(ctx context.Context) error {
	if mc.closed.Load() || mc.buf.busy() {
		return driver.ErrBadConn
	}

	// Perform a stale connection check. We only perform this check for
	// the first query on a connection that has been checked out of the
	// connection pool: a fresh connection from the pool is more likely
	// to be stale, and it has not performed any previous writes that
	// could cause data corruption, so it's safe to return ErrBadConn
	// if the check fails.
	// 执行陈旧连接检查。我们仅对从���接池中检出的连接的第一个查询执行此检查：
	// 来自池的新连接更有可能是陈旧的，并且它没有执行任何可能导致数据损坏的先前写入，
	// 因此如果检查失败，返回ErrBadConn是安全的。
	if mc.cfg.CheckConnLiveness {
		conn := mc.netConn
		if mc.rawConn != nil {
			conn = mc.rawConn
		}
		var err error
		if mc.cfg.ReadTimeout != 0 {
			err = conn.SetReadDeadline(time.Now().Add(mc.cfg.ReadTimeout))
		}
		if err == nil {
			err = connCheck(conn)
		}
		if err != nil {
			mc.log("closing bad idle connection: ", err)
			return driver.ErrBadConn
		}
	}

	return nil
}

// IsValid implements driver.Validator interface
// (From Go 1.15)
// IsValid实现了driver.Validator接口
// (来自Go 1.15)
func (mc *mysqlConn) IsValid() bool {
	return !mc.closed.Load() && !mc.buf.busy()
}

var _ driver.SessionResetter = &mysqlConn{}
var _ driver.Validator = &mysqlConn{}
