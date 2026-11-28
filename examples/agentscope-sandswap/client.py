# SPDX-License-Identifier: Apache-2.0
"""AgentScope's public MCPTool adapter with an owned, verified HTTP transport."""
import os
import ssl
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from agentscope.tool import MCPTool, Toolkit


@asynccontextmanager
async def connect(*, key=None, ca=None):
    url = os.environ.get("SANDSWAP_MCP_URL", "https://localhost:3000/mcp")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("SANDSWAP_MCP_URL must be HTTPS without credentials")
    key = key if key is not None else os.environ["SANDSWAP_API_KEY"]
    context = ssl.create_default_context()
    ca = ca if ca is not None else os.environ.get("SANDSWAP_CA")
    if ca:
        context.load_verify_locations(cafile=ca)
    async with httpx2.AsyncClient(
        verify=context,
        headers={"Authorization": f"Bearer {key}", "X-Sandswap-Api-Key": key},
        timeout=httpx2.Timeout(90),
        limits=httpx2.Limits(max_connections=8, max_keepalive_connections=8,
                            keepalive_expiry=None),
        follow_redirects=True,
        trust_env=False,
    ) as http:
        async with Client(streamable_http_client(url, http_client=http), mode="auto",
                          read_timeout_seconds=90) as session:
            catalog = await session.list_tools()
            tools = {t.name: MCPTool(mcp_name="sandswap", tool=t, session=session,
                                    timeout=90) for t in catalog.tools}
            yield tools, Toolkit(tools=list(tools.values()))


def text_content(chunk):
    return "\n".join(b.text for b in chunk.content if b.type == "text")
