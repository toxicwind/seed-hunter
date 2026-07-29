# Python compatibility

| Version | Status | Notes |
|---|---|---|
| 3.12 | primary dev/test target | all tools verified |
| 3.11 | fully supported | no 3.12-only syntax anywhere |
| 3.8–3.10 | AST fallback path | semantic layer's `ast` usage is the only
version-sensitive surface; `ast.get_docstring`/`ast.walk`/`ast.parse` work
on 3.8+. If you extend the tools with `ast.unparse`, guard it:

```python
try:
    text = ast.unparse(node)          # 3.9+
except AttributeError:                # 3.8 fallback
    import io, tokenize
    text = "<expr>"                   # or regex-extract from source segment
```

No `match` statements, no `X | Y` unions, no walrus-dependent logic, no
3.10+ stdlib calls are used. f-strings and pathlib are the floor (3.6+).
