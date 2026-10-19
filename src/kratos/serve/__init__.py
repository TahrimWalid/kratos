"""`kratos serve`: Kratos as a model in a chat client (Open WebUI, LibreChat, any OpenAI
client) and as an MCP server over HTTP (docs/phaseB/B.3).

Localhost by default; every request needs a Kratos client token; nothing reachable from
either door can change a machine (no approval-gated tool, no fix channel, no /evolve, no
finding decisions). See `kratos.serve.app` for the request gate and DESIGN "Chat clients".
"""
