#!/usr/bin/env python3
"""
Bottom-up summarization with parallel batch processing.

Processes functions level-by-level in the call graph:
1. Get batch of functions whose callees are all summarized
2. Process entire batch in parallel (they don't depend on each other)
3. Repeat until all functions are summarized
"""

import subprocess
import json
import sys
import time
import re
import sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

# Script directory for finding summarizer.py
SCRIPT_DIR = Path(__file__).parent
SUMMARIZER = str(SCRIPT_DIR / "summarizer.py")

# Globals set by main()
DB_PATH = ""
PROJECT_PATH = ""
MAX_WORKERS = 50


def run_summarizer(command: str, **kwargs) -> dict:
    """Run summarizer.py and return JSON result."""
    cmd = ["python", SUMMARIZER, "--db", DB_PATH, "--project", PROJECT_PATH]

    if command == "next-batch":
        cmd.extend(["next-batch", "--max", str(kwargs.get("max", 50))])
    elif command == "context":
        cmd.extend(["context", "--function-id", str(kwargs["function_id"])])
    elif command == "update":
        cmd.extend(["update", "--function", kwargs["function"], "--summary", kwargs["summary"]])
        if kwargs.get("function_id"):
            cmd.extend(["--function-id", str(kwargs["function_id"])])
    elif command == "annotate":
        cmd.extend(["annotate", "--function", kwargs["function"], "--type", kwargs["type"], "--text", kwargs["text"]])
        if kwargs.get("function_id"):
            cmd.extend(["--function-id", str(kwargs["function_id"])])
    elif command == "status":
        cmd.append("status")

    result = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=120)

    output = result.stdout
    try:
        json_match = re.search(r'\{[\s\S]*\}', output)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass

    return {"status": "error", "message": output[:500]}


def call_copilot(prompt: str) -> str:
    """Call copilot -p to get LLM response."""
    try:
        result = subprocess.run(
            ["copilot", "-p", prompt[:6000], "-s", "--allow-all"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )
        if result.returncode == 0 and result.stdout and result.stdout.strip():
            return result.stdout.strip()
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return ""


def build_summary_prompt(func_data: dict) -> str:
    """Build prompt for summary generation."""
    name = func_data.get("function", "")
    source = func_data.get("source_code", "")
    callees = func_data.get("callees", [])

    callee_section = ""
    if callees:
        callee_section = "\n\n## Callees (functions this calls):\n"
        for c in callees[:12]:
            summary = c.get("summary", "") or "No summary"
            callee_section += f"\n### {c['function']}\n{summary[:2500]}\n"

    prompt = f"""Analyze this function and write a concise summary paragraph, including relevant information from the callees.

## Function: {name}

## Source Code:
```c
{source[:35000]}
```
{callee_section}

Write a concise paragraph summary covering 1) the function's higher level purpose, 2) how outputs depend on inputs, 3) any global or shared state it reads or mutates, and 4) which callees have side effects or can fail. This summary will be used to test deep paths in the program, so include any details that are relevant to understanding the function's behavior in different contexts.

Reply with ONLY the summary paragraph, no headers or bullets."""

    return prompt


def build_annotations_prompt(func_data: dict, summary: str) -> str:
    """Build prompt for pre/post condition generation."""
    name = func_data.get("function", "")
    source = func_data.get("source_code", "")

    prompt = f"""Analyze this function and generate a comprehensive set of preconditions and postconditions.   
        1. **Preconditions** — constraints on inputs/state required for correct execution.
            Flag each as explicitly enforced or [MISSING GUARD].
        2. **Postconditions** — properties guaranteed after execution (distinguish guaranteed vs conditional).
        Think of using these pre and postconditions in **Violation scenarios** — concrete inputs that break implicitly assumed preconditions,
            with expected misbehavior. These will be used as seeds for adversarial test generation.
        Use variable names from the source. Use semi-formal predicate notation.

## Function: {name}
## Summary: {summary}

## Source Code:
```c
{source[:25000]}
```

Reply with this exact JSON format only:
{{
  "preconditions": ["condition 1", "condition 2"],
  "postconditions": ["condition 1", "condition 2"]
}}"""

    return prompt


def parse_annotations(response: str) -> tuple:
    """Parse pre/post conditions from LLM response."""
    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            data = json.loads(json_match.group())
            pre = data.get("preconditions", [])
            post = data.get("postconditions", [])
            if isinstance(pre, list) and isinstance(post, list):
                return pre, post
    except (json.JSONDecodeError, AttributeError):
        pass
    return [], []


def process_single_function(func_info: dict) -> dict:
    """
    Process a single function (runs in thread pool).
    Returns result dict with function_id, name, summary, annotations.
    """
    func_id = func_info["function_id"]
    name = func_info["name"]

    try:
        # Get full context (source code + callees)
        context = run_summarizer("context", function_id=func_id)
        if context.get("status") != "needs_summary":
            return {"function_id": func_id, "name": name, "status": "error", "message": "No context"}

        # Generate summary
        summary_prompt = build_summary_prompt(context)
        summary = call_copilot(summary_prompt)

        if not summary:
            # Fallback
            source = context.get("source_code", "")
            callees = context.get("callees", [])
            callee_names = [c["function"] for c in callees[:3]]
            summary = f"{name}: "
            if callee_names:
                summary += f"Calls {', '.join(callee_names)}. "
            summary += f"See source in {context.get('file', 'unknown')}."

        # Generate annotations
        ann_prompt = build_annotations_prompt(context, summary)
        ann_response = call_copilot(ann_prompt)
        preconditions, postconditions = parse_annotations(ann_response)

        return {
            "function_id": func_id,
            "name": name,
            "status": "ok",
            "summary": summary,
            "preconditions": preconditions[:3],
            "postconditions": postconditions[:3]
        }
    except Exception as e:
        return {"function_id": func_id, "name": name, "status": "error", "message": str(e)}


def save_results_to_db(results: List[dict]):
    """Save all results directly to database (faster than subprocess calls)."""
    conn = sqlite3.connect(DB_PATH)

    for r in results:
        if r.get("status") != "ok":
            continue

        func_id = r["function_id"]
        summary = r.get("summary", "")

        # Update summary
        conn.execute("UPDATE functions SET summary = ? WHERE function_id = ?", (summary, func_id))

        # Add preconditions
        for i, pre in enumerate(r.get("preconditions", [])):
            conn.execute(
                "INSERT INTO preconditions (function_id, condition_text, sequence_order) VALUES (?, ?, ?)",
                (func_id, pre, i)
            )

        # Add postconditions
        for i, post in enumerate(r.get("postconditions", [])):
            conn.execute(
                "INSERT INTO postconditions (function_id, condition_text, sequence_order) VALUES (?, ?, ?)",
                (func_id, post, i)
            )

    conn.commit()
    conn.close()


def process_batch(batch: List[dict], workers: int = MAX_WORKERS) -> List[dict]:
    """Process a batch of functions in parallel."""
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_func = {executor.submit(process_single_function, f): f for f in batch}

        for future in as_completed(future_to_func):
            func = future_to_func[future]
            try:
                result = future.result()
                results.append(result)
                status = "+" if result.get("status") == "ok" else "x"
                print(f"  {status} {result['name']} (id={result['function_id']})")
            except Exception as e:
                print(f"  x {func['name']} - Exception: {e}")
                results.append({"function_id": func["function_id"], "name": func["name"], "status": "error"})

    return results


def main():
    global DB_PATH, PROJECT_PATH, MAX_WORKERS

    import argparse
    parser = argparse.ArgumentParser(description="Parallel bottom-up summarization")
    parser.add_argument("--count", type=int, default=200, help="Max functions to process")
    parser.add_argument("--batch-size", type=int, default=50, help="Max batch size per level")
    parser.add_argument("--workers", type=int, default=50, help="Parallel workers")
    parser.add_argument("--db", type=str, required=True, help="Database path")
    parser.add_argument("--project", type=str, required=True, help="Project path")

    args = parser.parse_args()

    DB_PATH = args.db
    PROJECT_PATH = args.project
    MAX_WORKERS = args.workers

    # Show initial status
    status = run_summarizer("status")
    total = status.get('total_functions', 0)
    summarized = status.get('summarized', 0)
    print(f"Starting: {summarized}/{total} summarized ({status.get('remaining', 0)} remaining)")
    print(f"Workers: {MAX_WORKERS}, Batch size: {args.batch_size}")
    print()

    total_processed = 0
    level = 0

    while total_processed < args.count:
        # Get next batch of ready functions
        batch_result = run_summarizer("next-batch", max=args.batch_size)

        if batch_result.get("status") == "complete":
            print("All functions summarized!")
            break

        if batch_result.get("status") != "ok":
            print(f"Error getting batch: {batch_result.get('message')}")
            break

        batch = batch_result.get("batch", [])
        if not batch:
            print("No functions ready to process")
            break

        # Limit to remaining count
        remaining_count = args.count - total_processed
        batch = batch[:remaining_count]

        level += 1
        print(f"=== Level {level}: {len(batch)} functions (remaining: {batch_result.get('total_remaining', '?')}) ===")

        # Process batch in parallel
        start_time = time.time()
        results = process_batch(batch, MAX_WORKERS)
        elapsed = time.time() - start_time

        # Save results to database
        successful = [r for r in results if r.get("status") == "ok"]
        save_results_to_db(successful)

        total_processed += len(batch)
        print(f"  Completed {len(successful)}/{len(batch)} in {elapsed:.1f}s ({len(batch)/elapsed:.1f} func/s)")
        print()

    # Final status
    status = run_summarizer("status")
    print(f"Done: {status.get('summarized', 0)}/{status.get('total_functions', 0)} summarized")
    print(f"Processed {total_processed} functions this run")


if __name__ == "__main__":
    main()
