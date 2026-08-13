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
VALID_VERDICTS = {"REACHABLE", "UNREACHABLE", "NEEDS_REVIEW"}
VALID_REACHABILITY_TYPES = {"DIRECT", "ACROSS_BOUNDARY", "INDIRECT", None}

# 扩展名 → 语言 (与 ast_scanner.ASTCoarseScanner.EXTENSION_MAP 保持一致的子集)
_EXT_LANG = {
    ".java": "java", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp",
    ".h": "cpp", ".hpp": "cpp", ".py": "python", ".go": "go", ".rs": "rust",
    ".js": "javascript", ".ts": "javascript", ".jsx": "javascript", ".tsx": "javascript",
    ".cs": "csharp", ".php": "php", ".rb": "ruby", ".swift": "swift",
    ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".sh": "shell",
    ".pl": "perl", ".pm": "perl", ".ps1": "powershell",
}
_R15_IGNORE_DIRS = {"node_modules", ".git", ".audit_results", ".agents", ".codex",
                    ".venv", "__pycache__", "reachable-critical-audit", "build",
                    "target", "dist", "vendor", "third_party", "libs", "test",
                    "tests", "tool", "tools", "script", "scripts", "mock",
                    "mocks", "unittest", "scratch", "demo"}


def _profile_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "resources", "security_profiles.json")


def _detect_languages(project_root):
    """统计项目各语言源文件数，返回按文件数降序的语言列表。"""
    counts = {}
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in _R15_IGNORE_DIRS]
        for f in files:
            if ".min." in f:
                continue
            lang = _EXT_LANG.get(os.path.splitext(f)[1].lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return sorted(counts.keys(), key=lambda l: -counts[l]), counts


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


def _validate_verdict_payload(cand_id, payload):
    if not isinstance(payload, dict):
        return [f"{cand_id}: verdict must be a dict (kept PENDING for retry)"]

    errors = []
    missing = sorted(REQUIRED_VERDICT_KEYS - set(payload.keys()))
    if missing:
        errors.append(f"{cand_id}: missing required verdict keys {missing} (kept PENDING for retry)")

    if payload.get("verdict") not in VALID_VERDICTS:
        errors.append(f"{cand_id}: invalid verdict '{payload.get('verdict')}' (kept PENDING for retry)")

    if payload.get("reachability_type") not in VALID_REACHABILITY_TYPES:
        errors.append(f"{cand_id}: invalid reachability_type '{payload.get('reachability_type')}'")

    if "call_chain" in payload and not isinstance(payload.get("call_chain"), list):
        errors.append(f"{cand_id}: call_chain must be a list")

    if "call_chain_depth" in payload and not isinstance(payload.get("call_chain_depth"), int):
        errors.append(f"{cand_id}: call_chain_depth must be an integer")

    if "evidence" in payload and not isinstance(payload.get("evidence"), str):
        errors.append(f"{cand_id}: evidence must be a string")

    return errors


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
        # 非法条目：单独记入 errors 并跳过该条，但**不影响同批其他合法条目落盘**。
        # 出错的候选保持原有 PENDING 状态，下一轮 --stage next 会再次出队重试，
        # 绝不因批内个别坏 verdict 而丢弃整批已完成的工作。
        if cand_id not in cand_map:
            errors.append(f"Unknown candidate: {cand_id}")
            continue

        validation_errors = _validate_verdict_payload(cand_id, v)
        if validation_errors:
            errors.extend(validation_errors)
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

    # 只要有任何合法结果就落盘（部分成功优于整批丢弃）。
    save_queue(project_root, queue)
    remaining = len([c for c in candidates if c.get("status") == "PENDING"])
    result = {
        "status": "BATCH_COLLECTED" if not errors else "BATCH_COLLECTED_WITH_ERRORS",
        "batch_id": batch_id,
        "updated": updated,
        "errors": errors,
        "remaining_pending": remaining,
        "progress_pct": round((1 - remaining / len(candidates)) * 100, 1) if candidates else 0
    }
    print(json.dumps(result, ensure_ascii=False))


def stage_assert(project_root):
    """Assert no PENDING candidates remain."""
    queue = load_queue(project_root)
    candidates = queue["candidates"]
    pending = [c for c in candidates if c.get("status") == "PENDING"]
    needs_review = [c for c in candidates if c.get("verdict") == "NEEDS_REVIEW"]
    invalid_verified = []
    for c in candidates:
        if c.get("status") != "VERIFIED":
            continue
        verdict = c.get("verdict")
        if verdict not in VALID_VERDICTS:
            invalid_verified.append({"id": c.get("id"), "reason": "invalid verdict"})
            continue
        if verdict in ("REACHABLE", "UNREACHABLE"):
            if not isinstance(c.get("call_chain"), list) or c.get("call_chain_depth", 0) < MIN_CALL_CHAIN_DEPTH:
                invalid_verified.append({"id": c.get("id"), "reason": "insufficient call_chain_depth"})
            if not c.get("evidence"):
                invalid_verified.append({"id": c.get("id"), "reason": "missing evidence"})
        if verdict == "REACHABLE" and not c.get("reachability_type"):
            invalid_verified.append({"id": c.get("id"), "reason": "missing reachability_type"})
        if verdict == "UNREACHABLE" and not c.get("blocking_point"):
            invalid_verified.append({"id": c.get("id"), "reason": "missing blocking_point"})

    if pending:
        print(json.dumps({
            "status": "ASSERT_FAILED",
            "pending_count": len(pending),
            "pending_ids": [c.get("id") for c in pending],
            "needs_review_count": len(needs_review)
        }))
        sys.exit(2)

    if invalid_verified:
        print(json.dumps({
            "status": "ASSERT_FAILED_INVALID_VERIFIED",
            "invalid_count": len(invalid_verified),
            "invalid": invalid_verified[:50],
        }))
        sys.exit(3)

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


def _build_r15_prompt(lang, patterns, project_root):
    """构建 framework-sink-extractor 任务书 (R1.5, REQ-18)。"""
    pat_lines = []
    for group, globs in patterns.items():
        if group.startswith("_"):
            continue
        pat_lines.append(f"  - **{group}**: {', '.join(globs)}")
    pat_block = "\n".join(pat_lines) if pat_lines else "  (该语言无预置 wrapper 模式)"

    return f"""你是一个 framework-sink-extractor 子智能体 (R1.5 阶段)。你有完整的 grep/read 工具。

## 任务上下文
- **项目路径**: {project_root}
- **目标语言**: {lang}
- **wrapper_detection 模式** (名字匹配以下 glob 的、本项目自定义的函数/宏/方法):
{pat_block}

## 任务
1. 用 grep 在全项目 {lang} 源码中，找出**名字匹配上述模式**、且是**本项目自定义**（非第三方库）的函数/宏/方法定义与调用点。
2. 对每个匹配，判断它是否 wrapping 了 sink 性质：分配内存 / 执行命令 / 拼接 SQL / 跨进程调用 / 释放对象。
3. 判断远端/外部数据是否可能流入该 wrapper。
4. 只保留确实具备 sink 性质的 wrapper，忽略纯工具函数。

## 输出格式（强制 JSON，不要其他文字）
{{
  "extended_sinks": [
    {{
      "file": "相对路径",
      "line": 123,
      "wrapper_name": "osi_calloc",
      "matched_pattern": "allocator_pattern:osi_*",
      "inferred_sink_type": "CWE-789 UncontrolledMemoryAllocation",
      "remote_data_reachable": true,
      "evidence": "一句话说明为何是 sink 及数据来源"
    }}
  ]
}}
若确实未发现任何项目自有 wrapper sink，返回 {{"extended_sinks": []}}。"""


def stage_r15(project_root):
    """R1.5 框架感知扩展：输出各主要语言的 framework-sink-extractor 任务书。

    REQ-18 要求 R1.5 无条件执行、与 R1 互补。此 stage 生成任务书供 Agent 用
    task/Agent 工具拉起子智能体；结果经 --stage r15-collect 以 origin=L1 并入队列。
    """
    langs, counts = _detect_languages(project_root)
    with open(_profile_path(), encoding="utf-8") as f:
        wrapper_detection = json.load(f).get("wrapper_detection", {})

    tasks = []
    for lang in langs:
        patterns = wrapper_detection.get(lang)
        if not patterns:
            continue
        tasks.append({
            "language": lang,
            "source_file_count": counts[lang],
            "prompt": _build_r15_prompt(lang, patterns, project_root),
        })

    print(json.dumps({
        "status": "R15_READY" if tasks else "R15_NO_APPLICABLE_LANG",
        "detected_languages": langs,
        "language_file_counts": counts,
        "task_count": len(tasks),
        "note": "对每个 task 用 task/Agent 工具拉起 framework-sink-extractor 子智能体，"
                "收集其 extended_sinks JSON 后调用 --stage r15-collect 并入队列。",
        "tasks": tasks,
    }, indent=2, ensure_ascii=False))


def stage_r15_collect(project_root, sinks):
    """把 framework-sink-extractor 产出的 extended_sinks 以 origin=L1 并入 verify_queue。"""
    queue = load_queue(project_root)
    candidates = queue["candidates"]

    # 现有最大编号，续编 CAND-xxx
    max_n = 0
    for c in candidates:
        cid = c.get("id", "")
        if cid.startswith("CAND-"):
            try:
                max_n = max(max_n, int(cid.split("-")[1]))
            except (ValueError, IndexError):
                pass

    # 去重键：file+line+wrapper，避免与已有候选或重复并入
    existing_keys = {(c.get("file_path"), c.get("source_line"), c.get("source_pattern"))
                     for c in candidates}

    added = 0
    skipped_dup = 0
    for s in sinks:
        key = (s.get("file"), s.get("line"), s.get("wrapper_name"))
        if key in existing_keys:
            skipped_dup += 1
            continue
        existing_keys.add(key)
        max_n += 1
        cwe = (s.get("inferred_sink_type", "Unknown").split()[0]
               if s.get("inferred_sink_type") else "Unknown")
        candidates.append({
            "id": f"CAND-{max_n:03d}",
            "origin": "L1",
            "file_path": s.get("file", ""),
            "source_file": s.get("file", ""),
            "source_line": s.get("line", 0),
            "line_number": s.get("line", 0),
            "cwe_id": cwe,
            "sink_type": cwe,
            "category": s.get("inferred_sink_type", "FrameworkWrapper"),
            "source_pattern": s.get("wrapper_name", ""),
            "type": "TAINT_ANALYSIS",
            "matched_pattern": s.get("matched_pattern", ""),
            "sink_content": s.get("evidence", "")[:1000],
            "priority": 1,  # L1 wrapper 默认 P1
            "status": "PENDING",
            "verdict": None,
            "reachability_type": None,
            "blocking_point": None,
        })
        added += 1

    save_queue(project_root, queue)
    print(json.dumps({
        "status": "R15_COLLECTED",
        "added_L1": added,
        "skipped_duplicate": skipped_dup,
        "total_candidates": len(candidates),
    }, ensure_ascii=False))


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
        print("  python3 batch_verify.py <project_root> --stage r15")
        print("  python3 batch_verify.py <project_root> --stage r15-collect --sinks-file <path.json>")
        print("  python3 batch_verify.py <project_root> --stage next")
        print("  python3 batch_verify.py <project_root> --stage collect --batch <n> --cand-001='{...}' --cand-002='{...}'")
        print("  python3 batch_verify.py <project_root> --stage assert")
        print("  python3 batch_verify.py <project_root> --stage status")
        sys.exit(1)

    project_root = sys.argv[1]
    stage = None
    batch_id = None
    verdicts = {}
    sinks_file = None
    sinks_inline = None

    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == "--stage" and i + 1 < len(args):
            stage = args[i + 1]
        elif arg.startswith("--stage="):
            stage = arg.split("=", 1)[1]
        elif arg.startswith("--batch="):
            batch_id = int(arg.split("=", 1)[1])
        elif arg == "--batch" and i + 1 < len(args):
            batch_id = int(args[i + 1])
        elif arg.startswith("--sinks-file="):
            sinks_file = arg.split("=", 1)[1]
        elif arg == "--sinks-file" and i + 1 < len(args):
            sinks_file = args[i + 1]
        elif arg.startswith("--sinks="):
            sinks_inline = arg.split("=", 1)[1]
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

    if stage == "r15":
        stage_r15(project_root)
    elif stage == "r15-collect":
        # 从 --sinks-file 或 --sinks 读取 extended_sinks 列表
        raw = None
        if sinks_file:
            with open(sinks_file, encoding="utf-8") as f:
                raw = json.load(f)
        elif sinks_inline:
            raw = json.loads(sinks_inline)
        else:
            print("Error: r15-collect requires --sinks-file or --sinks", file=sys.stderr)
            sys.exit(1)
        # 兼容 {"extended_sinks":[...]} 与裸 [...]
        sinks = raw.get("extended_sinks", []) if isinstance(raw, dict) else raw
        stage_r15_collect(project_root, sinks)
    elif stage == "next":
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
