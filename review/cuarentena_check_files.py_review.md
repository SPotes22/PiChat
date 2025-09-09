<!-- hash:f243687755be8a55512bfc36c597330dad9bc62da95ce00930838c676222121a -->
# Code Review for check_files.py

```python
#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import shutil

# -------------------------------
# Carpetas a ignorar
# -------------------------------
IGNORE_DIRS = {"venv", ".git", "node_modules", "__pycache__", ".mypy_cache"}

# -------------------------------
# Filtros por stack para limpiar salida
# -------------------------------
FILTERS_BY_STACK = {
    "django": [
        (r"(SECRET_KEY\s*=\s*['\"].*?['\"])", "SECRET_KEY = '***REDACTED***'"),
        (r"(PASSWORD\s*=\s*['\"].*?['\"])", "PASSWORD = '***REDACTED***'"),
        (r"(API_KEY\s*=\s*['\"].*?['\"])", "API_KEY = '***REDACTED***'"),
        (r"(DEBUG\s*=\s*True)", r"\1  # DEV MODE: No usar en producción"),
        (r"(ALLOWED_HOSTS\s*=\s*\[.*?\])", "ALLOWED_HOSTS = ['*']  # DEV ONLY")
    ],
    "flask": [
        (r"(SECRET_KEY\s*=\s*['\"].*?['\"])", "SECRET_KEY = '***REDACTED***'"),
        (r"(SQLALCHEMY_DATABASE_URI\s*=\s*['\"].*?['\"])", "SQLALCHEMY_DATABASE_URI = '***REDACTED***'"),
        (r"(DEBUG\s*=\s*True)", r"\1  # DEV MODE: No usar en producción")
    ],
    "node": [
        (r"(process\.env\.(?:[A-Z_]+_?KEY|PASSWORD|TOKEN|SECRET)[^\n]*)", "/* ***REDACTED*** */"),
        (r"(['\"](?:AIza|sk-|ghp_)[A-Za-z0-9_\-]+['\"])", "'***REDACTED***'"),
        (r"(app\.listen\(\s*\d+\s*\))", r"\1 // DEV PORT, ajustar en producción")
    ],
    "react": [
        (r"(process\.env\.REACT_APP_[A-Z0-9_]+)", "/* ***REDACTED*** */"),
        (r"(https?:\/\/[^\s'\"]+\/api[^\s'\"]*)", "'***R
```

**Explanation:**

This Python script is designed to sanitize code in a project directory, primarily by redacting sensitive information like API keys, passwords, and secrets before sharing or committing the code to a public repository. It aims to prevent accidental exposure of credentials.

Here's a breakdown of the code's functionality:

1. **Imports:**
   - `os`:  Provides functions for interacting with the operating system (e.g., navigating directories, listing files).
   - `re`:  Enables regular expression operations for pattern matching and replacement in strings.  This is crucial for finding and redacting sensitive data.
   - `subprocess`: Allows running external commands (like `git status`) and capturing their output.
   - `sys`: Provides access to system-specific parameters and functions (e.g., command-line arguments).
   - `shutil`: Offers high-level file operations (e.g., copying files and trees).  While imported, it's not directly used in the snippet provided.  It's likely used in the full script, but the provided section doesn't show that usage.

2. **`IGNORE_DIRS`:**
   - `IGNORE_DIRS = {"venv", ".git", "node_modules", "__pycache__", ".mypy_cache"}`:  This is a set of directory names that the script will skip when traversing the project directory.  These directories typically contain:
     - `venv`: Python virtual environments (contains dependencies).
     - `.git`:  The Git repository directory (contains version control information).
     - `node_modules`:  Node.js dependencies (often very large).
     - `__pycache__`: Python bytecode cache directories.
     - `.mypy_cache`: MyPy cache directory

   Ignoring these directories speeds up the process and prevents the script from accidentally modifying files within them, which could break dependencies or version control.

3. **`FILTERS_BY_STACK`:**
   - This is a dictionary that holds regular expression-based filters for different technology stacks (e.g., "django", "flask", "node", "react").  The filters are used to identify and replace sensitive information in code files.
   - Each key in the dictionary represents a technology stack.
   - Each value is a list of tuples, where each tuple contains:
     - A regular expression pattern (as a string).
     - A replacement string.
   - **Example (Django):**
     - `(r"(SECRET_KEY\s*=\s*['\"].*?['\"])", "SECRET_KEY = '***REDACTED***'")`
       - This regular expression looks for lines of code that define a `SECRET_KEY` variable.  Specifically:
         - `SECRET_KEY`: Matches the literal string "SECRET_KEY".
         - `\s*=\s*`: Matches zero or more whitespace characters followed by an equals sign followed by zero or more whitespace characters.
         - `['\"]`: Matches either a single quote or a double quote.
         - `.*?`:  Matches any character (except newline) zero or more times, but as few times as possible (non-greedy). This matches the actual key.
         - `['\"]`: Matches the closing single or double quote.
       - The replacement string replaces the entire matched line with `SECRET_KEY = '***REDACTED***'`, effectively obscuring the actual secret key.
     - `(r"(DEBUG\s*=\s*True)", r"\1  # DEV MODE: No usar en producción")`
       -  This regex finds the line `DEBUG = True`.  The `\1` in the replacement string refers to the first captured group (in this case, the entire matched string: `DEBUG = True`). This adds a comment warning not to use the debug mode in production.
     - `(r"(ALLOWED_HOSTS\s*=\s*\[.*?\])", "ALLOWED_HOSTS = ['*']  # DEV ONLY")`
       -  This regex replaces the `ALLOWED_HOSTS` setting with `ALLOWED_HOSTS = ['*']`.  This is a common development setting, but is extremely insecure for production as it allows any host to access the application. The comment highlights that this is for development only.

   - **Other Stacks:** Similar filters are defined for Flask, Node.js, and React, targeting common places where secrets and sensitive data might be stored. The Node filters look for environment variables containing keys, passwords, tokens, or secrets, and also specifically looks for common API key prefixes (like "AIza", "sk-", "ghp_").  The React filters target environment variables prefixed with `REACT_APP_` and API endpoints.

**How the script is *likely* used (based on common patterns):**

The provided code snippet represents the **definition** of the filters and the ignored directories.  A larger script would typically:

1. **Take a directory as input** (using `sys.argv` to get a command-line argument).
2. **Walk through the directory tree** (using `os.walk`).
3. **Identify the technology stack** used in the project (likely through heuristics like checking for certain files, e.g., `manage.py` for Django, `package.json` for Node.js).
4. **Based on the detected stack, apply the appropriate filters** from `FILTERS_BY_STACK` to each file:
   - Read the file content.
   - Iterate through the regex patterns in the stack's filter list.
   - Use `re.sub()` to find and replace matches with the corresponding replacement string.
   - Write the modified content back to the file.
5. **Optionally, create a new sanitized directory** (copying the original and modifying in place). This is where `shutil` would be used.

**In summary:**

This script is a code sanitizer that helps prevent the accidental disclosure of sensitive information by automatically redacting or modifying potentially sensitive data within a project's codebase.  It uses regular expressions and stack-specific filters to target common locations where secrets are stored.  It's a crucial tool for security-conscious developers who need to share or publish their code without exposing their credentials.
