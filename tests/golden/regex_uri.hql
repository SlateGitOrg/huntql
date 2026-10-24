http | where uri =~ "^/submit\\.php" | stats count(), first(method) as method by host, user_agent
