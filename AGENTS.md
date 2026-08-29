# Permguard Repository Instructions

## Project Architecture

Permguard is a policy management system that keeps authorization policies in a content-addressed, Git-like ledger. It distributes signed versions over a protocol built for it and answers "can this subject do this to this?" either from its own data plane or from inside your process at zero network cost.

## Coding Conventions

- Rust 1.97+ required
- Workspace-based Cargo setup with multiple crates
- Comprehensive documentation in README.md
- Strict adherence to licensing requirements (Apache-2.0)

## Testing Instructions

- Run workspace tests with `task test` or `make test`
- Run linting with `task lint` or `make lint`
- Check core dependencies with `task check:core-deps`
- Run coverage checks with `task coverage`

## Git Conventions

- Follow standard Git workflows
- Use descriptive commit messages
- Keep commits focused on single changes
- Use tags for releases

## Security Constraints

- Security configuration in `deny.toml` with specific license allowances
- Strict dependency management using `cargo deny`
- Configuration files marked with proper copyright and license headers

## Shared Agent Resources

- Shared skills in `.agents/skills/`
- Shared rules in `.agents/rules/`
- Shared tools in `.agents/tools/`
- Shared scripts in `.agents/scripts/`
- Project knowledge in `.agents/knowledge/`

## Knowledge System

The `.agents/knowledge/` directory contains structured documentation that agents can use to understand repository context:

### Design Patterns
- `.agents/knowledge/design-patterns.md` - Repository design patterns and architectural decisions

### Repository Conventions
- `.agents/knowledge/repository-conventions.md` - Coding conventions, git workflows, etc.

### Domain Knowledge  
- `.agents/knowledge/domain-specific.md` - Technical domain knowledge relevant to this repository

### API Documentation
- `.agents/knowledge/apis.md` - API specifications and interfaces

### Architecture
- `.agents/knowledge/architecture.md` - System architecture diagrams and explanations

## Where Project Knowledge Lives

- Primary documentation: README.md
- Extended documentation: docs/ directory
- Generic repository knowledge: `.agents/knowledge/`
- API documentation: `.agents/knowledge/apis.md`
- Design patterns: `.agents/knowledge/design-patterns.md`
- Repository conventions: `.agents/knowledge/repository-conventions.md`

## Where Shared Tools/Scripts Live

- Shared scripts: .agents/scripts/
- Portable tools: .agents/tools/