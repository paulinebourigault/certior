---
name: research
description: Search public AI safety research and summarise findings
homepage: https://example.com/research-skill
metadata:
  openclaw:
    requires:
      env: ["TAVILY_API_KEY"]
  certior:
    capabilities:
      - "network:http:read"
---

When the user asks for AI research, use the `web_search` tool…
