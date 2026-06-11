---
name: writer
description: Compose markdown documents from a structured outline
metadata:
  openclaw:
    requires:
      bins: ["pandoc"]
  certior:
    capabilities:
      - "filesystem:read"
      - "filesystem:write"
---

When the user asks for a written document, use the `compose` tool…
