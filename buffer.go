// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2013 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"io"
	"net"
	"time"
)

const defaultBufSize = 4096
const maxCachedBufSize = 256 * 1024

// A buffer which is used for both reading and writing.
// This is possible since communication on each connection is synchronous.
// In other words, we can't write and read simultaneously on the same connection.
// The buffer is similar to bufio.Reader / Writer but zero-copy-ish
// Also highly optimized for this particular use case.
// This buffer is backed by two byte slices in a double-buffering scheme
// 用于读写的缓冲区。
// 这是可能的，因为每个连接上的通信是同步的。
// 换句话说，我们不能在同一连接上同时进行读写。
// 该缓冲区类似于bufio.Reader / Writer，但更接近于零拷贝
// 也为这种特定用例进行了高度优化。
// 该缓冲区由双缓冲方案中的两个字节切片支持
type buffer struct {
	buf     []byte // buf是一个字节缓冲区，其长度和容量相等。
	nc      net.Conn
	idx     int
	length  int
	timeout time.Duration
	dbuf    [2][]byte // dbuf是一个包含两个字节切片的数组，这些切片支持此缓冲区
	flipcnt uint      // flipcnt是双缓冲的当前缓冲区计数器
}

// newBuffer allocates and returns a new buffer.
// newBuffer分配并返回一个新的缓冲区。
func newBuffer(nc net.Conn) buffer {
	fg := make([]byte, defaultBufSize)
	return buffer{
		buf:  fg,
		nc:   nc,
		dbuf: [2][]byte{fg, nil},
	}
}

// busy returns true if the buffer contains some read data.
// 如果缓冲区包含一些读取数据，则busy返回true。
func (b *buffer) busy() bool {
	return b.length > 0
}

// flip replaces the active buffer with the background buffer
// this is a delayed flip that simply increases the buffer counter;
// the actual flip will be performed the next time we call `buffer.fill`
// flip用背景缓冲区替换活动缓冲区
// 这是一个延迟翻转，只是增加缓冲区计数器；
// 实际翻转将在我们下次调用`buffer.fill`时执行
func (b *buffer) flip() {
	b.flipcnt += 1
}

// fill reads into the buffer until at least _need_ bytes are in it
// fill读取缓冲区，直到其中至少有_need_字节
func (b *buffer) fill(need int) error {
	n := b.length
	// fill data into its double-buffering target: if we've called
	// flip on this buffer, we'll be copying to the background buffer,
	// and then filling it with network data; otherwise we'll just move
	// the contents of the current buffer to the front before filling it
	// 将数据填充到其双缓冲目标：如果我们在此缓冲区上调用了flip，
	// 我们将复制到背景缓冲区，然后用网络数据填充它；
	// 否则，我们只会在填充之前将当前缓冲区的内容移到前面
	dest := b.dbuf[b.flipcnt&1]

	// grow buffer if necessary to fit the whole packet.
	// 如果需要，增长缓冲区以适应整个数据包。
	if need > len(dest) {
		// Round up to the next multiple of the default size
		// 向上舍入到默认大小的下一个倍数
		dest = make([]byte, ((need/defaultBufSize)+1)*defaultBufSize)

		// if the allocated buffer is not too large, move it to backing storage
		// to prevent extra allocations on applications that perform large reads
		// 如果分配的缓冲区不太大，将其移动到后备存储
		// 以防止在执行大读取的应用程序上进行额外分配
		if len(dest) <= maxCachedBufSize {
			b.dbuf[b.flipcnt&1] = dest
		}
	}

	// if we're filling the fg buffer, move the existing data to the start of it.
	// if we're filling the bg buffer, copy over the data
	// 如果我们正在填充fg缓冲区，请将现有数据移到其开头。
	// 如果我们正在填充bg缓冲区，请复制数据
	if n > 0 {
		copy(dest[:n], b.buf[b.idx:])
	}

	b.buf = dest
	b.idx = 0

	for {
		if b.timeout > 0 {
			if err := b.nc.SetReadDeadline(time.Now().Add(b.timeout)); err != nil {
				return err
			}
		}

		nn, err := b.nc.Read(b.buf[n:])
		n += nn

		switch err {
		case nil:
			if n < need {
				continue
			}
			b.length = n
			return nil

		case io.EOF:
			if n >= need {
				b.length = n
				return nil
			}
			return io.ErrUnexpectedEOF

		default:
			return err
		}
	}
}

// returns next N bytes from buffer.
// The returned slice is only guaranteed to be valid until the next read
// 从缓冲区返回下一个N字节。
// 返回的切片仅保证在下次读取之前有效
func (b *buffer) readNext(need int) ([]byte, error) {
	if b.length < need {
		// refill
		// 重新填充
		if err := b.fill(need); err != nil {
			return nil, err
		}
	}

	offset := b.idx
	b.idx += need
	b.length -= need
	return b.buf[offset:b.idx], nil
}

// takeBuffer returns a buffer with the requested size.
// If possible, a slice from the existing buffer is returned.
// Otherwise a bigger buffer is made.
// Only one buffer (total) can be used at a time.
// takeBuffer返回具有请求大小的缓冲区。
// 如果可能，从现有缓冲区返回一个切片。
// 否则，创建一个更大的缓冲区。
// 一次只能使用一个缓冲区（总计）。
func (b *buffer) takeBuffer(length int) ([]byte, error) {
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}

	// test (cheap) general case first
	// 首先测试（便宜的）一般情况
	if length <= cap(b.buf) {
		return b.buf[:length], nil
	}

	if length < maxPacketSize {
		b.buf = make([]byte, length)
		return b.buf, nil
	}

	// buffer is larger than we want to store.
	// 缓冲区大于我们想要存储的。
	return make([]byte, length), nil
}

// takeSmallBuffer is shortcut which can be used if length is
// known to be smaller than defaultBufSize.
// Only one buffer (total) can be used at a time.
// takeSmallBuffer是一个快捷方式，如果长度已知小于defaultBufSize，则可以使用。
// 一次只能使用一个缓冲区（总计）。
func (b *buffer) takeSmallBuffer(length int) ([]byte, error) {
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}
	return b.buf[:length], nil
}

// takeCompleteBuffer returns the complete existing buffer.
// This can be used if the necessary buffer size is unknown.
// cap and len of the returned buffer will be equal.
// Only one buffer (total) can be used at a time.
// takeCompleteBuffer返回完整的现有缓冲区。
// 如果必要的缓冲区大小未知，可以使用此方法。
// 返回的缓冲区的cap和len将相等。
// 一次只能使用一个缓冲区（总计）。
func (b *buffer) takeCompleteBuffer() ([]byte, error) {
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}
	return b.buf, nil
}

// store stores buf, an updated buffer, if its suitable to do so.
// store存储buf，一个更新的缓冲区，如果适合这样做。
func (b *buffer) store(buf []byte) error {
	if b.length > 0 {
		return ErrBusyBuffer
	} else if cap(buf) <= maxPacketSize && cap(buf) > cap(b.buf) {
		b.buf = buf[:cap(buf)]
	}
	return nil
}
