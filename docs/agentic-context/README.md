# Agentic Context Documentation

This directory contains detailed technical documentation for AI agents and developers working on the honeypot detector codebase.

## Purpose

These files provide deep context about:
- Implementation details
- Architecture decisions
- Development progress
- Test results
- Integration guides
- Technical specifications

## Files in This Directory

### 1. `IMPLEMENTATION_PROGRESS.md`
**Purpose**: Complete development history and architecture documentation

**Contents**:
- Phase-by-phase implementation timeline
- MCP server architecture (TypeScript)
- Rust integration layer details
- Prompt engineering documentation
- Code statistics and file locations
- Original requirements and design decisions

**Use When**:
- Understanding project architecture
- Continuing development work
- Making architectural decisions
- Debugging integration issues

### 2. `INTEGRATION_COMPLETE.md`
**Purpose**: Final integration summary and completion report

**Contents**:
- What was built (complete inventory)
- Code statistics (~2,640 lines)
- Architecture diagrams
- Testing status
- Known issues and limitations
- Next steps (Phase 6+)
- Deployment checklist
- Success criteria verification

**Use When**:
- Getting up to speed on current state
- Planning next development phases
- Understanding what's complete vs. TODO
- Deployment planning

### 3. `TEST_RESULTS.md`
**Purpose**: MCP server testing documentation

**Contents**:
- All 21 test results from MCP server
- Tool-by-tool validation
- Pattern detection test cases
- Real contract testing (WPLS, PLSX)
- Performance metrics (<3s per analysis)

**Use When**:
- Validating MCP server functionality
- Debugging tool failures
- Understanding test coverage
- Adding new test cases

## User-Facing Documentation (Root Directory)

The following files should remain in the project root for end users:

- **`README.md`** - Main user documentation, quick start, usage
- **`CLAUDE_INTEGRATION.md`** - Claude setup guide, API reference, troubleshooting
- **`POOL_TRACKER_USAGE.md`** - Pool tracking feature documentation

## For AI Agents

When continuing development on this project:

### Quick Context Loading

1. **First Time**: Read `INTEGRATION_COMPLETE.md` for current state
2. **Understanding Architecture**: Read `IMPLEMENTATION_PROGRESS.md` 
3. **Before Testing**: Review `TEST_RESULTS.md`
4. **For Users**: Reference root-level documentation

### Development Workflow

```
┌─────────────────────────────────────────────────────────────┐
│  Agent receives task                                        │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │  Read relevant docs │
              │  from this folder   │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │  Make changes       │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │  Update docs here   │
              │  if needed          │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │  Update user docs   │
              │  in root if needed  │
              └─────────────────────┘
```

### Key Principles

1. **Never modify user docs** unless adding user-facing features
2. **Always update this folder** when making architectural changes
3. **Keep context current** - update `IMPLEMENTATION_PROGRESS.md` for major changes
4. **Document decisions** - explain "why" not just "what"
5. **Test results go here** - keep `TEST_RESULTS.md` current

## File Organization Strategy

### Root Level (User-Facing)
```
README.md                    - Quick start, usage, examples
CLAUDE_INTEGRATION.md        - Claude setup, API reference
POOL_TRACKER_USAGE.md        - Feature documentation
```

### `docs/agentic-context/` (Developer/Agent)
```
README.md                    - This file
IMPLEMENTATION_PROGRESS.md   - Architecture & development history
INTEGRATION_COMPLETE.md      - Current state & completion status
TEST_RESULTS.md              - Testing documentation
```

### `prompts/` (Claude Prompts)
```
system_prompt.md             - Core detection guidelines
quick_mode.md                - Fast analysis prompts
hybrid_mode.md               - Adaptive analysis prompts
deep_mode.md                 - Exhaustive analysis prompts
```

### `mcp-server/` (TypeScript MCP Server)
```
honeypot-tools.ts            - MCP server implementation
test-*.ts                    - Test suites
package.json                 - Dependencies
```

## Current Project State (December 4, 2025)

**Status**: Phase 5 Complete (Integration), Phase 6 Ready (Claude API)

**Completion**: ~85%

**What Works**:
- ✅ MCP server (21/21 tests passing)
- ✅ Rust integration layer (compiles successfully)
- ✅ CLI arguments
- ✅ Caching system
- ✅ Token budget tracking
- ✅ Graceful degradation
- ✅ Ensemble voting

**What's Missing** (Critical):
- ⚠️ Actual Claude API calls (currently mock data)
- ⚠️ Real token usage tracking from Claude
- ⚠️ Production testing with real tokens

**Next Phase**: Phase 6 - Implement `call_claude_api()` (~2-3 hours)

## Contributing

When adding new features or fixing bugs:

1. Read relevant docs from this folder first
2. Make your changes
3. Update `IMPLEMENTATION_PROGRESS.md` if architectural
4. Update `INTEGRATION_COMPLETE.md` if completing TODO items
5. Update `TEST_RESULTS.md` if adding/modifying tests
6. Update root-level docs only if user-visible changes

## Questions?

For technical questions about implementation:
- Check `IMPLEMENTATION_PROGRESS.md` first
- Review code comments
- Check Git history for context

For usage questions:
- Check root-level `README.md` or `CLAUDE_INTEGRATION.md`

---

**This folder is for agents/developers. User documentation lives in project root.**
