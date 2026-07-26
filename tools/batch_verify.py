#!/usr/bin/env python3
"""
batch_verify.py — R3 批量验证编排器 (Mode A' for opencode/Claude Code)

设计原则：
  - 只做调度和记账，不做分析
  - 每个候选通过 task 子智能体独立验证（有完整的 grep/read 能力）
  - 每批完成后立即落盘，支持断点续传
  - 最后 assert 无 PENDING 残留

用法 (由 Agent 驱动):
  1. 读取下一批:
     python3 batch_verify.py /path/to/project --stage next
     → 输出 3-4 个候选的任务书 + 批次号

  2. Agent 并发执行 task:
     task(subagent_type="general", description=..., prompt=...)
     ...

  3. 收集结果:
     python3 batch_verify.py /path/to/project --stage collect \\
       --batch <n> --cand-001='{"verdict":"REACHABLE",...}' \\
       --cand-002='{"verdict":"UNREACHABLE",...}'
     → 更新 verify_queue.json, 写回磁盘

  4. 重复 1-3 直到 --stage assert 通过

  5. 最终断言:
     python3 batch_verify.py /path/to/project --stage assert
     → 0 PENDING → exit 0
     → 有 PENDING → exit 2 + 列出未验证候选
"""

import json
import os
import sys
import glob

BATCH_SIZE = 4
REQUIRED_VERDICT_KEYS = {"verdict", "reachability_type", "call_chain", "call_chain_depth", "evidence"}
MIN_CALL_CHAIN_DEPTH = 3


def load_queue(project_root):
    path = os.path.join(project_root, ".audit_results", "verify_queue.json")
    with open(path) as f:
        raw = json.load(f)
    if isinstance(raw, dict) and "candidates" in raw:
        return raw
    return {"schema_version": "2.0", "candidates": raw}


def save_queue(project_root, queue):
    path = os.path.join(project_root, ".audit_results", "verify_queue.json")
    # Normalize to dict form if needed
    if isinstance(queue, list):
        queue = {"schema_version": "2.0", "candidates": queue}
    with open(path, "w") as f:
        json.dump(queue, f, indent=2, ensure_ascii=False)


def stage_next(project_root):
    """Find next batch of PENDING candidates and print task prompts."""
    queue = load_queue(project_root)
    candidates = queue["candidates"]

    pending = [c for c in candidates if c.get("status") == "PENDING"]
    if not pending:
        print(json.dumps({"status": "ALL_DONE", "message": "No pending candidates remaining"}))
        return

    # 按优先级排序: P0(最高) → P3(最低), 无优先级的放最后
    priority_key = lambda c: c.get("priority", 99)
    pending.sort(key=priority_key)

    batch = pending[:BATCH_SIZE]
    batch_info = {
        "status": "BATCH_READY",
        "batch_id": _next_batch_id(project_root),
        "count": len(batch),
        "total_pending": len(pending),
        "total_candidates": len(candidates),
        "tasks": []
    }

    for i, cand in enumerate(batch):
        # Get context for the task prompt
        ctx = _build_context(cand)
        task = {
            "index": i,
            "candidate_id": cand["id"],
            "file": cand.get("file_path", "?"),
            "line": cand.get("source_line", cand.get("line_number", "?")),
            "cwe": cand.get("cwe_id", "?"),
            "category": cand.get("category", "?"),
            "type": cand.get("type", "TAINT_ANALYSIS"),
            "language": cand.get("language", "?"),
            "prompt": _build_prompt(cand, ctx, project_root)
        }
        batch_info["tasks"].append(task)

    print(json.dumps(batch_info, indent=2, ensure_ascii=False))


def stage_collect(project_root, batch_id, verdicts):
    """Collect verdicts from a batch and update the queue."""
    queue = load_queue(project_root)
    candidates = queue["candidates"]
    cand_map = {c.get("id"): c for c in candidates}

    updated = 0
    errors = []
    for cand_id, v in verdicts.items():
        if cand_id not in cand_map:
            errors.append(f"Unknown candidate: {cand_id}")
            continue
        # Validate verdict structure
        if not isinstance(v, dict):
            errors.append(f"{cand_id}: verdict must be a dict")
            continue
        if v.get("verdict") not in ("REACHABLE", "UNREACHABLE", "NEEDS_REVIEW"):
            errors.append(f"{cand_id}: invalid verdict '{v.get('verdict')}'")
            continue

        # Validate call chain depth
        call_chain = v.get("call_chain", [])
        depth = v.get("call_chain_depth", len(call_chain))
        if v["verdict"] in ("REACHABLE", "UNREACHABLE") and depth < MIN_CALL_CHAIN_DEPTH:
            # Depth too shallow: upgrade to NEEDS_REVIEW and flag for retry
            v["verdict"] = "NEEDS_REVIEW"
            v["evidence"] = (v.get("evidence", "") +
                f" [AUTO: call_chain_depth={depth} < {MIN_CALL_CHAIN_DEPTH}, requires deeper backtracking]")

        entry = cand_map[cand_id]
        entry["status"] = "VERIFIED"
        entry["verdict"] = v["verdict"]
        entry["reachability_type"] = v.get("reachability_type")
        entry["call_chain"] = call_chain
        entry["call_chain_depth"] = depth
        entry["evidence"] = v.get("evidence", "")
        entry["blocking_point"] = v.get("blocking_point")
        entry["path_count"] = v.get("path_count", 0)
        entry["paths_analyzed"] = v.get("paths_analyzed", [])
        entry["verified_at"] = __import__("datetime").datetime.now().isoformat()
        # Preserve CWE from rule if not overridden
        if v.get("cwe"):
            entry["cwe"] = v["cwe"]
        updated += 1

    if errors:
        print(json.dumps({"status": "COLLECT_ERRORS", "errors": errors}))
        return

    save_queue(project_root, queue)
    remaining = len([c for c in candidates if c.get("status") == "PENDING"])
    print(json.dumps({
        "status": "BATCH_COLLECTED",
        "batch_id": batch_id,
        "updated": updated,
        "remaining_pending": remaining,
        "progress_pct": round((1 - remaining / len(candidates)) * 100, 1) if candidates else 0
    }))


def stage_assert(project_root):
    """Assert no PENDING candidates remain."""
    queue = load_queue(project_root)
    candidates = queue["candidates"]
    pending = [c for c in candidates if c.get("status") == "PENDING"]
    needs_review = [c for c in candidates if c.get("verdict") == "NEEDS_REVIEW"]

    if pending:
        print(json.dumps({
            "status": "ASSERT_FAILED",
            "pending_count": len(pending),
            "pending_ids": [c.get("id") for c in pending],
            "needs_review_count": len(needs_review)
        }))
        sys.exit(2)

    reachable = [c for c in candidates if c.get("verdict") == "REACHABLE"]
    unreachable = [c for c in candidates if c.get("verdict") == "UNREACHABLE"]

    # Calculate average call chain depth
    depths = [c.get("call_chain_depth", 0) for c in candidates if c.get("call_chain_depth")]
    avg_depth = round(sum(depths) / len(depths), 2) if depths else 0

    print(json.dumps({
        "status": "ASSERT_PASSED",
        "total": len(candidates),
        "reachable": len(reachable),
        "unreachable": len(unreachable),
        "needs_review": len(needs_review),
        "avg_call_chain_depth": avg_depth,
        "min_call_chain_depth": min(depths) if depths else 0,
        "max_call_chain_depth": max(depths) if depths else 0,
        "reachability_rate_pct": round(len(reachable) / len(candidates) * 100, 2) if candidates else 0,
        "noise_reduction_rate_pct": round(len(unreachable) / len(candidates) * 100, 2) if candidates else 0,
        "warning": "call chain depth below threshold" if avg_depth < MIN_CALL_CHAIN_DEPTH else None
    }))


def stage_status(project_root):
    """Print queue status summary."""
    queue = load_queue(project_root)
    candidates = queue["candidates"]
    statuses = {}
    verdicts = {}
    cwes = {}
    for c in candidates:
        s = c.get("status", "UNSET")
        statuses[s] = statuses.get(s, 0) + 1
        v = c.get("verdict", "UNSET")
        verdicts[v] = verdicts.get(v, 0) + 1
        cwe = c.get("cwe_id", "?")
        cwes[cwe] = cwes.get(cwe, 0) + 1

    priorities = {}
    for c in candidates:
        p = c.get("priority", 99)
        priorities[p] = priorities.get(p, 0) + 1

    print(json.dumps({
        "status": "QUEUE_STATUS",
        "total": len(candidates),
        "by_status": statuses,
        "by_verdict": verdicts,
        "by_priority": dict(sorted(priorities.items())),
        "by_cwe": dict(sorted(cwes.items(), key=lambda x: -x[1])[:15])
    }))


def _next_batch_id(project_root):
    """Find the next batch number for continuation."""
    existing = glob.glob(os.path.join(project_root, ".audit_results", "batch_*.json"))
    nums = []
    for p in existing:
        try:
            nums.append(int(os.path.basename(p).split("_")[1].split(".")[0]))
        except (ValueError, IndexError):
            pass
    return max(nums) + 1 if nums else 1


def _build_context(cand):
    """Build a concise context summary for the task prompt."""
    ctx = {
        "file": cand.get("file_path", "?"),
        "line": cand.get("source_line", cand.get("line_number", "?")),
        "sink": cand.get("sink_content", "")[:200],
        "language": cand.get("language", "?"),
        "cwe": cand.get("cwe_id", "?"),
        "category": cand.get("category", "?"),
        "type": cand.get("type", "?"),
        "sources_regex": cand.get("sources_regex", []),
        "verification_logic": cand.get("verification_logic", ""),
        "reachability_constraints": cand.get("reachability_constraints", ""),
    }
    return ctx


def _build_prompt(cand, ctx, project_root):
    """Build the task prompt for a vulnerability-verifier subagent.
    
    The subagent has full access to read, grep, and explore tools.
    This prompt only provides context — it does NOT constrain how
    the subagent verifies the finding.
    """
    is_property_check = cand.get("type") == "PROPERTY_CHECK"

    prompt = f"""你是一个 vulnerability-verifier 子智能体。你有完整的代码阅读和分析工具（read、grep 等）。

## 任务上下文
- **候选 ID**: {cand["id"]}
- **文件**: {ctx["file"]}:{ctx["line"]}
- **语言**: {ctx["language"]}
- **CWE**: {ctx["cwe"]} ({ctx["category"]})
- **Sink 代码**: `{ctx["sink"]}`
"""
    if ctx["sources_regex"]:
        prompt += f"- **Source 正则**: {ctx['sources_regex']}\n"
    prompt += f"- **项目路径**: {project_root}\n"

    prompt += f"""
## 强制分析步骤（语言无关）

### 步骤 1: 逆向调用链回溯（最小深度 3 层）
1. 读取 {ctx['file']} L{ctx['line']} 周围代码，确认 sink 点
2. 使用 grep 反向查找直接调用者（Caller_L1），记录调用处 file:line:function
3. 追踪 Caller_L1 的每个参数来源，找到 Caller_L2
4. 重复直到追溯到外部输入源（请求参数/文件/Binder IPC/蓝牙 HCI 事件等）
5. **质量门禁**: call_chain 必须 >= 3 层（Sink ← L1 ← L2），不足则继续向上搜索

### 步骤 2: 多态穿透
遇接口/抽象类/虚函数/特征(trait)，搜索所有具体实现类继续回溯

### 步骤 3: 跨边界判定
调用链到达任何进程/IPC/跨模块边界时，边界即 sink：
- 自由文本参数来自外部输入拼接 → REACHABLE_ACROSS_BOUNDARY
- 强制参数化/类型安全/白名单 → UNREACHABLE

### 步骤 4: 阻断检测
- 强类型转换、掩码（`& 0xFF`）、参数化绑定（`?` 占位符）、边界检查（`offset+len <= total`）
- 阻断必须覆盖所有攻击者可控制维度——多维度中只要有一维无阻断，仍为 REACHABLE

### 步骤 5: 路径覆盖
- 列出所有到达该 Sink 点的调用路径
- 多条路径中只要有一条无阻断 → 该点 REACHABLE

### 步骤 6: 结论
无法明确判定 → NEEDS_REVIEW（不允许默认判定或静默丢弃）
"""
    prompt += """## 输出格式（强制 JSON，不要其他文字）
{
  "verdict": "REACHABLE | UNREACHABLE | NEEDS_REVIEW",
  "reachability_type": "DIRECT | ACROSS_BOUNDARY | INDIRECT",
  "call_chain": ["file:line:function", "file:line:function", "file:line:function", ...],
  "call_chain_depth": <int>,
  "blocking_point": "file:line / null",
  "path_count": <int>,
  "paths_analyzed": ["path1 description", ...],
  "evidence": "包含调用链和每层数据流路径分析的说明",
  "cwe": ["CWE-xxx"]
}
"""
    return prompt


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 batch_verify.py <project_root> --stage next")
        print("  python3 batch_verify.py <project_root> --stage collect --batch <n> --cand-001='{...}' --cand-002='{...}'")
        print("  python3 batch_verify.py <project_root> --stage assert")
        print("  python3 batch_verify.py <project_root> --stage status")
        sys.exit(1)

    project_root = sys.argv[1]
    stage = None
    batch_id = None
    verdicts = {}

    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == "--stage" and i + 1 < len(sys.argv):
            stage = sys.argv[i + 1]
        elif arg.startswith("--batch="):
            batch_id = int(arg.split("=", 1)[1])
        elif arg.startswith("--batch") and i + 1 < len(sys.argv):
            # --batch <n>
            batch_id = int(sys.argv[i + 1])
        elif arg.startswith("--cand-"):
            parts = arg.split("=", 1)
            if len(parts) == 2:
                # --cand-001=... → CAND-001
                num = parts[0].replace("--cand-", "")
                cand_id = f"CAND-{num}"
                try:
                    verdicts[cand_id] = json.loads(parts[1])
                except json.JSONDecodeError as e:
                    print(f"Error parsing {parts[0]}: {e}", file=sys.stderr)
                    sys.exit(1)

    if not stage:
        print("Error: --stage is required", file=sys.stderr)
        sys.exit(1)

    if stage == "next":
        stage_next(project_root)
    elif stage == "collect":
        if not verdicts:
            print("Error: --cand-XXX JSON arguments required for collect", file=sys.stderr)
            sys.exit(1)
        stage_collect(project_root, batch_id or 0, verdicts)
    elif stage == "assert":
        stage_assert(project_root)
    elif stage == "status":
        stage_status(project_root)
    else:
        print(f"Error: unknown stage '{stage}'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
