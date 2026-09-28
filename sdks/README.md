# AuditGuard SDKs

These SDKs are publish-ready source packages; they are not published to PyPI or npm by this change.

## Python

```bash
pip install -e sdks/python
```

```python
from auditguard import AuditGuard

guard = AuditGuard()
clean_prompt, is_safe = guard.protect("User input with email@example.com")
```

## JavaScript / TypeScript

```bash
npm install ./sdks/javascript
```

```js
const { AuditGuard } = require('auditguard');
const guard = new AuditGuard();
const result = await guard.protect(userInput);
```
