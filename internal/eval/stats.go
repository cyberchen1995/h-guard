package eval

import "math"

// Wilson 返回比例 k/n 的 Wilson 95% 置信区间（z = 1.96）。n 为 0 时没有信息，返回 [0, 1]。
// 小样本下 Wilson 比正态近似可靠，且 k = 0 或 k = n 时区间不会退化成一个点。
func Wilson(k, n int) (lo, hi float64) {
	if n == 0 {
		return 0, 1
	}
	return wilsonRate(float64(k)/float64(n), n)
}

// wilsonRate 返回比例 p 在样本量 n 下的 Wilson 95% 区间。--repeat 时 p 按拼接后的全部结论算，n 却只数独立语料：
// 同一条语料跑 K 次不是 K 条新语料，重复不能让区间变窄（评审 R2-01）。
func wilsonRate(p float64, n int) (lo, hi float64) {
	if n == 0 {
		return 0, 1
	}
	const z = 1.96
	nf := float64(n)
	denom := 1 + z*z/nf
	center := (p + z*z/(2*nf)) / denom
	half := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf)) / denom
	return math.Max(0, center-half), math.Min(1, center+half)
}

// Calibratable 报告 o 的结论是否随阈值变化：后端被调用、没有失败、每题都有有效答案。
// deny 级规则直接拒绝、无命中直接放行的语料不问后端，它们的结论与阈值无关；
// 调用失败或缺题的结论来自保守处理，也不是阈值决定的。
func (o Outcome) Calibratable() bool { return o.Called && o.Err == "" && o.Invalid == 0 }

// EffectiveN 返回结论随阈值变化的条数（校准有效 n）。置信区间与 margin 的解读都要看它，而不是条目总数。
func EffectiveN(outs []Outcome) int {
	n := 0
	for _, o := range outs {
		if o.Calibratable() {
			n++
		}
	}
	return n
}
