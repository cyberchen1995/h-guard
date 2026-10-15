package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// object 是保持键顺序的 JSON 对象：改写 harness 的配置（~/.claude/settings.json、~/.codex/hooks.json）时只动
// 本项目的键，其余键的顺序与取值原样保留（值按原文保存，只重新缩进）。
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

// parseObject 解析一个 JSON 对象；不是对象、语法错误、重复的键都报错（不猜用户的意图，也不覆盖读不懂的文件）。
func parseObject(b []byte) (object, error) {
	o := object{vals: map[string]json.RawMessage{}}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return o, fmt.Errorf("not a JSON object: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return o, errors.New("not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return o, err
		}
		key := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return o, err
		}
		if _, dup := o.vals[key]; dup {
			return o, fmt.Errorf("duplicate key %q", key)
		}
		o.keys, o.vals[key] = append(o.keys, key), v
	}
	if _, err := dec.Token(); err != nil {
		return o, err
	}
	if len(bytes.TrimSpace(b[dec.InputOffset():])) > 0 {
		return o, errors.New("trailing data after the JSON object")
	}
	return o, nil
}

func (o *object) get(key string) (json.RawMessage, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// set 设置 key 的值（新键加在末尾）。
func (o *object) set(key string, v any) {
	b, _ := json.Marshal(v)
	o.setRaw(key, b)
}

func (o *object) setRaw(key string, v json.RawMessage) {
	if o.vals == nil {
		o.vals = map[string]json.RawMessage{}
	}
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

func (o *object) delete(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// object 返回 key 下的对象；没有这个键时返回空对象；值不是对象时报错。
func (o *object) object(key string) (object, error) {
	v, ok := o.vals[key]
	if !ok || string(bytes.TrimSpace(v)) == "null" {
		return object{vals: map[string]json.RawMessage{}}, nil
	}
	sub, err := parseObject(v)
	if err != nil {
		return sub, fmt.Errorf("%s: %w", key, err)
	}
	return sub, nil
}

func (o *object) setObject(key string, sub object) error {
	o.setRaw(key, sub.compact())
	return nil
}

func (o object) compact() json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// marshal 以两个空格缩进输出，末尾带换行。
func (o object) marshal() []byte {
	var b bytes.Buffer
	_ = json.Indent(&b, o.compact(), "", "  ")
	b.WriteByte('\n')
	return b.Bytes()
}
