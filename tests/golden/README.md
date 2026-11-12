# Golden packet

`sample-packet.html` is the byte-for-byte render of `examples/sample-snapshot.json`
with the timestamp pinned to `2026-11-12 12:00 UTC` (the injectable clock in
`practice_render.render.render`).

Regenerate after an intentional markup or CSS change:

```bash
UPDATE_GOLDEN=1 uv run --no-project --with pytest pytest -q tests/test_render_golden.py
```

Review the diff before committing. The golden file must stay a self-contained,
script-free document with no external references.
