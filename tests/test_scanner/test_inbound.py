from airiskguard_gateway.scanner.inbound.vuln_code import scan_inbound_vuln_code
from airiskguard_gateway.models import Severity, Category


def test_detects_sql_injection_in_code_block():
    text = """
Here's a function to fetch a user:

```python
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
```
"""
    findings = scan_inbound_vuln_code(text)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("sql" in f.title.lower() for f in findings)


def test_detects_command_injection():
    text = """
```python
import os
def run_tool(user_input):
    os.system(f"convert {user_input} output.png")
```
"""
    findings = scan_inbound_vuln_code(text)
    assert any("command injection" in f.title.lower() for f in findings)


def test_detects_hardcoded_secret_in_code():
    text = """
```python
api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
client = OpenAI(api_key=api_key)
```
"""
    findings = scan_inbound_vuln_code(text)
    assert any(f.category == Category.VULNERABLE_CODE for f in findings)


def test_detects_weak_crypto():
    text = """
```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
```
"""
    findings = scan_inbound_vuln_code(text)
    assert any("weak" in f.title.lower() for f in findings)


def test_clean_code_no_findings():
    text = """
```python
def add(a: int, b: int) -> int:
    return a + b
```
"""
    findings = scan_inbound_vuln_code(text)
    assert len(findings) == 0
