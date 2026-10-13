package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ApplyDotEnv 读取 configDir/.env，把其中尚未在环境中设置的变量写入进程环境（与 Python 版
// load_dotenv(override=False) 一致，spec §8.6）。hook 在任意 cwd 下运行，所以不读当前目录的 .env。
// 文件不存在时什么都不做。值不会被打印或记录。
func ApplyDotEnv(configDir string) error {
	f, err := os.Open(filepath.Join(configDir, ".env"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := parseDotEnvLine(sc.Text())
		if !ok {
			continue
		}
		if _, set := os.LookupEnv(key); set {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return sc.Err()
}

// parseDotEnvLine 解析 KEY=VALUE、export KEY=VALUE，去掉成对的单双引号；空行与注释返回 ok=false。
func parseDotEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")
	key, value, ok = strings.Cut(line, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}
