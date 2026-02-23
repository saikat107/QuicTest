---
name: semantic-indexer
description: Build semantic code indexes using tree-sitter parsing and nested call graphs. Extract focal functions with their complete call graphs into SQLite database, then perform bottom-up summarization using actual source code + callee summaries. Database grows incrementally as you index more focal functions.
---

# Semantic Code Indexer

Parse codebases with tree-sitter, extract focal functions with nested call graphs, and perform bottom-up summarization using **actual source code** and callee context.

## Complete Workflow

### Step 1: Build Focal Function Call Graph

```bash
python scripts/build_focal.py \
  --focal "DnsQueryEx" \
  --file "querystub.c" \
  --project ~/dns_full \
  --db dns.db
```

### Step 2: Bottom-Up Summarization and pre-/post-condition Annotation

Run the batch summarizer to automatically process all functions in parallel:

```bash
python scripts/batch_summarize.py \
  --db dns.db \
  --project ~/dns_full \
  --count 500 \
  --batch-size 50 \
  --workers 50
```

**Parameters:**
- `--db`: Path to the SQLite database (required)
- `--project`: Path to the project root directory (required)
- `--count`: Maximum number of functions to process (default: 200)
- `--batch-size`: Functions per batch/level (default: 50)
- `--workers`: Parallel workers for LLM calls (default: 50)

The batch summarizer:
1. Finds functions whose callees are all summarized (ready for processing)
2. Processes them in parallel using an LLM
3. Generates summaries and pre/post conditions automatically
4. Saves results to the database
5. Repeats until all functions are summarized

#### Manual Summarization (Alternative)

For manual control or to fix specific functions, use the iterative approach:

```bash
# Get next function to summarize
python scripts/summarizer.py --db dns.db --project ~/dns_full next

# Update with your summary
python scripts/summarizer.py --db dns.db update \
  --function "LogError" \
  --summary "Logs error messages by initializing variable argument processing with va_start, passing formatted arguments to fnsVaLog at LOG_ERROR level, then cleaning up with va_end"

# Add annotations
python scripts/summarizer.py --db dns.db annotate \
  --function "LogError" \
  --type precondition \
  --text "fmt is a valid format string"
```

#### Tips for Good Summaries

**Summary Format:**
Write a concise paragraph summary covering the function's purpose, how outputs depend on inputs, any global or shared state it reads or mutates, and which callees have side effects, can fail, or contain complex branching that a test might need to exercise.

**Best Practices:**
1. **Actually read the source code** - Don't just rely on function names
2. **Use callee summaries** - They tell you what dependencies do and their important behaviors
3. **Look for control flow** - Loops, conditions, error handling
4. **Note side effects** - File I/O, global state, logging, network calls
5. **Be specific** - "Validates X by checking Y" not "Validates input"

**Preconditions** should cover:
- Required contracts on input parameters (e.g., non-empty list, non-null fields)
- Required environment/state
- Assumptions about invariants (e.g., IDs are unique, timestamps are monotonic)

**Postconditions** should cover:
- Return value guarantees (type/shape, relationships between fields)
- State changes (files written, DB rows updated, caches mutated)
- Error behavior (what exceptions/errors can occur and under what inputs/states)

### Check Progress

```bash
python scripts/summarizer.py --db dns.db status
```

```json
{
  "total_functions": 89,
  "summarized": 67,
  "remaining": 22,
  "progress_percent": 75.3,
  "leaf_functions": 18,
  "call_edges": 234
}
```

-------------
