set NODE_OPTIONS=--use-system-ca
npx mcp-remote http://localhost:5253/bot 63113 --static-oauth-client-info "{\"client_id\":\"mcp-remote\"}"
