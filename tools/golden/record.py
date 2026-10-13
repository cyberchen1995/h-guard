"""在 Python 版 h-guard（h-guard.old）中录制 golden 样本（spec §13）。

对语料逐条运行 Python 版的完整判断：正则 → （非 deny 时）真实调用 Jev → decide()，记录
「输入 + 发给模型的 state + Jev 的答案 + Python 的最终结论」。Go 版在
internal/check/action/golden_test.go 中离线回放这些答案，结论须逐条一致。

用法（在本仓库根目录，用 h-guard.old 的虚拟环境运行）：

    ../h-guard.old/.venv/bin/python -I tools/golden/record.py --old ../h-guard.old \
        --out testdata/golden/commands.jsonl            # 真实调用 Jev，需要 TYPESAFE_API_KEY，需维护者同意
    ../h-guard.old/.venv/bin/python -I tools/golden/record.py --old ../h-guard.old \
        --fake --out /tmp/golden-fake.jsonl            # 不联网：确定性的伪答案，用于先核对移植

不记录 API key；state 由 Python 的 build_state 生成，凭据已被遮蔽。cwd 固定为 /home/dev/project，
不写入本机路径。录制前核对 h-guard.old 的语料与固定清单 testdata/golden/corpus.json 逐条一致；
--fake 的录制模型名为 fake，不能写到正式录制的位置，Go 的正式验收也拒绝它。真实录制中有调用失败、
或答案缺题、为 null 时退出码为 1（Go 的正式验收按题逐一校验，这里只是提前提示）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

CWD = "/home/dev/project"

# 伪答案的取值：覆盖否决、中间地带、命中、授权与影响范围下限两侧
FAKE_P = [0.0, 0.1, 0.2, 0.25, 0.49, 0.5, 0.6, 0.9, 1.0]
FAKE_REQUESTED = [0.0, 0.3, 0.69, 0.7, 0.95]
FAKE_RADIUS = [
    [1.0, 0.0, 0.0, 0.0],
    [0.0, 1.0, 0.0, 0.0],
    [0.0, 0.75, 0.25, 0.0],
    [0.0, 0.7, 0.3, 0.0],
    [0.0, 0.5, 0.5, 0.0],
    [0.0, 0.0, 0.0, 1.0],
]


def pick(options, *key):
    digest = hashlib.sha256("|".join(map(str, key)).encode()).digest()
    return options[digest[0] % len(options)]


def fake_ask(seed, case_id, rule_ids):
    """确定性的伪答案；每 17 条有一条模拟不可用。规则答案多数为低分，少数命中，贴近真实分布。"""
    if (case_id + seed) % 17 == 0:
        return SimpleNamespace(response=None, error="ReadTimeout", latency_ms=None)
    nouls = {rid: SimpleNamespace(noul=pick(FAKE_P if pick([0, 1, 1], seed, case_id, rid, "hot") == 0 else [0.0, 0.05, 0.1],
                                            seed, case_id, rid)) for rid in rule_ids}
    nouls["explicitly_requested"] = SimpleNamespace(noul=pick(FAKE_REQUESTED, seed, case_id, "req"))
    probs = pick(FAKE_RADIUS, seed, case_id, "radius")
    score = sum(i * p for i, p in enumerate(probs))
    scores = {"blast_radius": SimpleNamespace(score=score, probabilities=dict(enumerate(probs)))}
    return SimpleNamespace(response=SimpleNamespace(nouls=nouls, scores=scores, model="fake"), error=None, latency_ms=None)


def complete(answers, expected) -> bool:
    """每道题都有非 null 的答案，blast_radius 的分布没有 null 项。"""
    if not answers or not expected <= set(answers) or any(v is None for v in answers.values()):
        return False
    return None not in answers["blast_radius"].get("probabilities", [None])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True, help="h-guard.old 仓库路径")
    ap.add_argument("--out", required=True)
    ap.add_argument("--fake", action="store_true", help="不调用 Jev，使用确定性的伪答案")
    ap.add_argument("--seed", type=int, default=0, help="--fake 的种子")
    ap.add_argument("--corpus", default="testdata/golden/corpus.json", help="固定语料清单（Go 测试钉住它的 SHA-256）")
    args = ap.parse_args()
    formal_out = Path("testdata/golden/commands.jsonl").resolve()
    if args.fake and Path(args.out).resolve() == formal_out:
        print("--fake must not write the formal recording", file=sys.stderr)
        return 2

    sys.path.insert(0, str(Path(args.old) / "src"))
    from h_guard import judge
    from h_guard.config import load_config
    from h_guard.evaluate import load_corpus
    from h_guard.patterns import match_command
    from h_guard.policy import decide
    from h_guard.state import build_state

    config = load_config(None)
    cases = load_corpus(Path(args.old) / "src" / "h_guard" / "corpus" / "commands.jsonl")
    with open(args.corpus, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if len(manifest) != len(cases):
        print(f"corpus has {len(cases)} cases, manifest {len(manifest)}", file=sys.stderr)
        return 2
    out = []
    for case_id, case in enumerate(cases, 1):
        command = case["command"]
        requests = [case["user_request"]] if case.get("user_request") else []
        want = manifest[case_id - 1]
        if (want["id"], want["command"], want["user_requests"], want["cwd"]) != (case_id, command, requests, CWD):
            print(f"case {case_id}: h-guard.old corpus does not match the manifest", file=sys.stderr)
            return 2
        regex = match_command(command, config)
        rec = {
            "id": case_id, "command": command, "user_requests": requests, "expect": case["expect"],
            "note": case.get("note", ""), "cwd": CWD, "regex": sorted(m.rule_id for m in regex),
            "state": None, "answers": None, "error": None, "model": None,
        }
        if any(m.action == "deny" for m in regex):
            verdict = decide(regex, None, config, user_requests=requests)
        else:
            state = build_state(command=command, cwd=CWD, tool="Bash", harness="generic",
                                user_requests=requests, config=config)
            rec["state"] = state
            if args.fake:
                result = fake_ask(args.seed, case_id, list(config.rules))
            else:
                result = judge.ask(state, config, timeout=judge.PATIENT_TIMEOUT_SECONDS, retry=judge.PATIENT_RETRY)
            rec["error"] = result.error
            if result.response is not None:
                resp = result.response
                rec["model"] = resp.model
                answers = {rid: a.noul for rid, a in resp.nouls.items()}
                br = resp.scores.get("blast_radius")
                if br is not None:
                    n = len(config.signals["blast_radius"].criteria)
                    answers["blast_radius"] = {
                        "score": br.score,
                        "probabilities": [br.probabilities.get(i) for i in range(n)],
                    }
                rec["answers"] = answers
            verdict = decide(regex, result.response, config, user_requests=requests, jev_error=result.error)
        rec["decision"] = verdict.decision
        rec["matched"] = sorted(m.rule_id for m in verdict.matched)
        rec["signals"] = verdict.signals
        rec["fallback"] = verdict.fallback
        out.append(rec)
        print(f"{case_id:3d} {verdict.decision:4s} {command[:70]}", file=sys.stderr)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in out:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    errors = sum(1 for r in out if r["error"])
    expected = set(config.rules) | {"explicitly_requested", "blast_radius"}
    incomplete = sum(1 for r in out if r["state"] is not None and not r["error"] and not complete(r["answers"], expected))
    print(f"recorded {len(out)} cases, {errors} judge errors, {incomplete} incomplete answers", file=sys.stderr)
    return 1 if (errors or incomplete) and not args.fake else 0


if __name__ == "__main__":
    sys.exit(main())
