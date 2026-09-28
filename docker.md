# Constrói o Servidor OAuth Central
docker build -t mcp-oauth-server -f Dockerfile.server .

# Constrói o Servidor MCP Local
docker build -t mcp-server-real -f Dockerfile.mcp .
