set NODE_TLS_REJECT_UNAUTHORIZED=0
npx mcp-remote http://localhost:5253/bot 63113 --static-oauth-client-info "{\"client_id\":\"mcp-remote\"}"
