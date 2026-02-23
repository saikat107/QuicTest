#!/usr/bin/env python3
"""
Bottom-up summarization workflow
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

import query_repo
from indexer import SemanticIndex


def find_next_summary_target(index: SemanticIndex, entry_id: int, visited: set) -> Tuple[Optional[Dict], bool]:
    """
    Post-order traversal to find next node to summarize.
    
    Returns (target_node, is_subtree_summarized)
    - target_node: First unsummarized node whose callees are all summarized
    - is_subtree_summarized: True if this subtree is fully summarized
    """
    if entry_id in visited:
        # Already visited - check if it's summarized
        func = index.get_function_info(entry_id)
        if func and func["summary"].strip():
            return None, True
        return None, False
    
    visited.add(entry_id)
    
    # Get function info
    func = index.get_function_info(entry_id)
    if not func:
        return None, True  # Unknown function treated as summarized
    
    # Get callees
    callees = index.get_callees(entry_id)
    
    # Check if this node is already summarized
    is_summarized = bool(func["summary"].strip())
    
    if is_summarized:
        # Already summarized - check callees to continue traversal
        all_callees_done = True
        for callee in callees:
            target, subtree_done = find_next_summary_target(index, callee["function_id"], visited)
            if target:
                return target, False
            if not subtree_done:
                all_callees_done = False
        return None, all_callees_done
    
    # Not summarized yet - check if all callees are done (post-order)
    all_callees_summarized = True
    for callee in callees:
        target, subtree_done = find_next_summary_target(index, callee["function_id"], visited)
        if target:
            # Found a target in subtree - return it
            return target, False
        if not subtree_done:
            all_callees_summarized = False
    
    # If all callees are summarized (or no callees), this is our target
    if all_callees_summarized:
        return func, False
    
    # Some callees not summarized yet
    return None, False


def get_next_target(index: SemanticIndex) -> Dict[str, Any]:
    """
    Find next function to summarize (bottom-up)
    RETURNS ACTUAL SOURCE CODE for the agent to read!
    """
    
    # Get all functions (roots of any focal trees)
    cursor = index.conn.execute("SELECT DISTINCT function_id FROM functions")
    all_funcs = [row[0] for row in cursor]
    
    if not all_funcs:
        return {
            "status": "error",
            "message": "No functions in database"
        }
    
    # Try each function as a potential root
    visited = set()
    for func_id in all_funcs:
        target, complete = find_next_summary_target(index, func_id, visited)
        if target:
            # Get callee summaries
            callees = index.get_callees(target["function_id"])
            
            # Get source code using query_repo
            source_code = query_repo.query_function(
                target["name"], 
                target["file"] if target["file"] != "unknown" else None
            )
            
            if not source_code:
                source_code = "Function code not found."
            
            # Get pre/postconditions
            cursor = index.conn.execute(
                """SELECT condition_text FROM preconditions 
                   WHERE function_id = ? ORDER BY sequence_order""",
                (target["function_id"],)
            )
            preconditions = [row[0] for row in cursor]
            
            cursor = index.conn.execute(
                """SELECT condition_text FROM postconditions 
                   WHERE function_id = ? ORDER BY sequence_order""",
                (target["function_id"],)
            )
            postconditions = [row[0] for row in cursor]
            
            # Get callee summaries with their callees (nested one level for context)
            callees_with_context = []
            for c in callees:
                callee_info = {
                    "function": c["function"],
                    "file": c["file"],
                    "summary": c["summary"]
                }
                # Get sub-callees for additional context
                sub_callees = index.get_callees(c["function_id"])
                if sub_callees:
                    callee_info["calls"] = [
                        {"function": sc["function"], "summary": sc["summary"]} 
                        for sc in sub_callees[:3]  # Limit to first 3 for brevity
                    ]
                callees_with_context.append(callee_info)
            
            return {
                "status": "needs_summary",
                "function_id": target["function_id"],
                "function": target["name"],
                "file": target["file"],
                "start_line": target["start_line"],
                "end_line": target["end_line"],
                "source_code": source_code,  # ← ACTUAL SOURCE CODE!
                "preconditions": preconditions,
                "postconditions": postconditions,
                "callees": callees_with_context,
                "summary_instructions": "Write a concise paragraph summary covering the function's purpose, how outputs depend on inputs, any global or shared state it reads or mutates, and which callees have side effects, can fail, or contain complex branching that a test might need to exercise."
            }
    
    # All functions summarized
    return {
        "status": "complete",
        "message": "All functions in database are summarized"
    }


def update_summary(index: SemanticIndex, function_name: str, summary: str, function_id: Optional[int] = None) -> Dict:
    """Update function summary"""

    func_id = function_id
    if not func_id:
        # Find function by name
        cursor = index.conn.execute(
            "SELECT function_id FROM functions WHERE name = ? LIMIT 1",
            (function_name,)
        )
        row = cursor.fetchone()
        func_id = row[0] if row else None

    if not func_id:
        return {
            "status": "error",
            "message": f"Function not found: {function_name}"
        }

    index.update_summary(func_id, summary)

    return {
        "status": "ok",
        "function_id": func_id,
        "function": function_name,
        "summary": summary
    }


def add_annotation(
    index: SemanticIndex,
    function_name: str,
    ann_type: str,
    text: str,
    function_id: Optional[int] = None
) -> Dict:
    """Add precondition or postcondition"""

    func_id = function_id
    if not func_id:
        # Find function by name
        cursor = index.conn.execute(
            "SELECT function_id FROM functions WHERE name = ? LIMIT 1",
            (function_name,)
        )
        row = cursor.fetchone()
        func_id = row[0] if row else None

    if not func_id:
        return {
            "status": "error",
            "message": f"Function not found: {function_name}"
        }

    table = "preconditions" if ann_type == "precondition" else "postconditions"

    # Get next sequence number
    cursor = index.conn.execute(
        f"SELECT COALESCE(MAX(sequence_order), -1) + 1 FROM {table} WHERE function_id = ?",
        (func_id,)
    )
    seq = cursor.fetchone()[0]

    # Insert
    index.conn.execute(
        f"INSERT INTO {table} (function_id, condition_text, sequence_order) VALUES (?, ?, ?)",
        (func_id, text, seq)
    )
    index.conn.commit()

    return {
        "status": "ok",
        "function": function_name,
        "type": ann_type,
        "text": text
    }


def get_status(index: SemanticIndex) -> Dict:
    """Get summarization progress"""
    stats = index.get_stats()

    total = stats["total_functions"]
    summarized = stats["summarized_functions"]
    remaining = total - summarized
    progress = (summarized / total * 100) if total > 0 else 0

    return {
        "total_functions": total,
        "summarized": summarized,
        "remaining": remaining,
        "progress_percent": round(progress, 1),
        "leaf_functions": stats["leaf_functions"],
        "call_edges": stats["total_call_edges"]
    }


def get_next_batch(index: SemanticIndex, max_batch: int = 50) -> Dict[str, Any]:
    """
    Get batch of functions ready for parallel summarization.
    Returns functions whose callees are all summarized.
    """
    # Find functions that need summaries but whose callees are all done
    cursor = index.conn.execute("""
        SELECT f.function_id, f.name, f.file
        FROM functions f
        WHERE f.summary = ''
        AND NOT EXISTS (
            SELECT 1 FROM call_edges ce
            JOIN functions callee ON ce.callee_id = callee.function_id
            WHERE ce.caller_id = f.function_id
            AND callee.summary = ''
        )
        LIMIT ?
    """, (max_batch,))

    batch = [
        {"function_id": row[0], "name": row[1], "file": row[2]}
        for row in cursor
    ]

    if not batch:
        # Check if all done or stuck
        cursor = index.conn.execute(
            "SELECT COUNT(*) FROM functions WHERE summary = ''"
        )
        remaining = cursor.fetchone()[0]

        if remaining == 0:
            return {"status": "complete", "message": "All functions summarized"}
        else:
            return {
                "status": "blocked",
                "message": f"{remaining} functions remaining but have unsummarized callees",
                "remaining": remaining
            }

    # Get total remaining count
    cursor = index.conn.execute(
        "SELECT COUNT(*) FROM functions WHERE summary = ''"
    )
    total_remaining = cursor.fetchone()[0]

    return {
        "status": "ok",
        "batch": batch,
        "batch_size": len(batch),
        "total_remaining": total_remaining
    }


def get_function_context(index: SemanticIndex, function_id: int) -> Dict[str, Any]:
    """
    Get full context for a specific function by ID.
    Returns source code and callee summaries for summarization.
    """
    func = index.get_function_info(function_id)
    if not func:
        return {"status": "error", "message": f"Function not found: {function_id}"}

    # Check if already summarized
    if func["summary"].strip():
        return {"status": "already_summarized", "function": func["name"]}

    # Get callees
    callees = index.get_callees(function_id)

    # Get source code using query_repo
    source_code = query_repo.query_function(
        func["name"],
        func["file"] if func["file"] != "unknown" else None
    )

    if not source_code:
        source_code = "Function code not found."

    # Get pre/postconditions
    cursor = index.conn.execute(
        """SELECT condition_text FROM preconditions
           WHERE function_id = ? ORDER BY sequence_order""",
        (function_id,)
    )
    preconditions = [row[0] for row in cursor]

    cursor = index.conn.execute(
        """SELECT condition_text FROM postconditions
           WHERE function_id = ? ORDER BY sequence_order""",
        (function_id,)
    )
    postconditions = [row[0] for row in cursor]

    # Get callee summaries with nested context
    callees_with_context = []
    for c in callees:
        callee_info = {
            "function": c["function"],
            "file": c["file"],
            "summary": c["summary"]
        }
        sub_callees = index.get_callees(c["function_id"])
        if sub_callees:
            callee_info["calls"] = [
                {"function": sc["function"], "summary": sc["summary"]}
                for sc in sub_callees[:3]
            ]
        callees_with_context.append(callee_info)

    return {
        "status": "needs_summary",
        "function_id": function_id,
        "function": func["name"],
        "file": func["file"],
        "start_line": func["start_line"],
        "end_line": func["end_line"],
        "source_code": source_code,
        "preconditions": preconditions,
        "postconditions": postconditions,
        "callees": callees_with_context
    }


def main():
    parser = argparse.ArgumentParser(
        description="Bottom-up summarization with SOURCE CODE context"
    )
    parser.add_argument("--db", required=True, help="Database file")
    parser.add_argument("--project", help="Project path (for query_repo if not already initialized)")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # next
    subparsers.add_parser("next", help="Get next function to summarize (WITH SOURCE CODE!)")
    
    # update
    update_parser = subparsers.add_parser("update", help="Update function summary")
    update_parser.add_argument("--function", required=True, help="Function name")
    update_parser.add_argument("--summary", required=True, help="Summary text")
    update_parser.add_argument("--function-id", type=int, help="Function ID (optional, faster lookup)")

    # annotate
    ann_parser = subparsers.add_parser("annotate", help="Add annotation")
    ann_parser.add_argument("--function", required=True, help="Function name")
    ann_parser.add_argument("--type", required=True, choices=["precondition", "postcondition"])
    ann_parser.add_argument("--text", required=True, help="Condition text")
    ann_parser.add_argument("--function-id", type=int, help="Function ID (optional, faster lookup)")
    
    # status
    subparsers.add_parser("status", help="Show summarization progress")

    # next-batch (for parallel processing)
    batch_parser = subparsers.add_parser("next-batch", help="Get batch of functions ready for parallel summarization")
    batch_parser.add_argument("--max", type=int, default=50, help="Maximum batch size")

    # context (get context for specific function by ID)
    context_parser = subparsers.add_parser("context", help="Get context for a specific function by ID")
    context_parser.add_argument("--function-id", type=int, required=True, help="Function ID")

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize query_repo if needed (for source code retrieval)
    if args.command == "next" and args.project:
        query_repo.init(args.project)
    
    index = SemanticIndex(args.db)
    
    if args.command == "next":
        result = get_next_target(index)
        print(json.dumps(result, indent=2))
    
    elif args.command == "update":
        func_id = getattr(args, 'function_id', None)
        result = update_summary(index, args.function, args.summary, func_id)
        print(json.dumps(result, indent=2))

    elif args.command == "annotate":
        func_id = getattr(args, 'function_id', None)
        result = add_annotation(index, args.function, args.type, args.text, func_id)
        print(json.dumps(result, indent=2))
    
    elif args.command == "status":
        result = get_status(index)
        print(json.dumps(result, indent=2))

    elif args.command == "next-batch":
        result = get_next_batch(index, args.max)
        print(json.dumps(result, indent=2))

    elif args.command == "context":
        result = get_function_context(index, args.function_id)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
