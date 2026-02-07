"""
Backend Security Auditor — a READ-ONLY static analysis security scanner.

This tool scans user-provided codebases for security misconfigurations using
regex pattern matching. It does NOT execute any code, make network requests,
access credentials, or perform any dangerous operations. It reads source files
and reports findings as JSON.

Similar to tools like Semgrep, Bandit, or ESLint security plugins.
"""
