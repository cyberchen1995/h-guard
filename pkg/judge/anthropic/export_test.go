package anthropic

// SetGetenv 让测试替换读取 API key 的方式，不改进程环境。
func (b *Backend) SetGetenv(f func(string) string) { b.getenv = f }
