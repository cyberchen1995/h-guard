// Package jsonl 读取 harness 会话记录（每行一个 JSON）的末尾，供 transcript 回退使用。
package jsonl

import (
	"bufio"
	"bytes"
	"io"
	"os"
)

// Tail 逐行读取 path 末尾的至多 max 字节，对每个完整的行调用 fn。从文件中间开始时第一行可能不完整，跳过。
// 读到的数据不超过 max，所以单行不会超过扫描缓冲；读取出错时返回错误（已经交给 fn 的行不撤回）。
func Tail(path string, max int64, fn func(line []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	start := info.Size() - max
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if start > 0 { // 第一行可能不完整
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), int(max))
	for sc.Scan() {
		fn(sc.Bytes())
	}
	return sc.Err()
}
