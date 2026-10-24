ssl | where endswith(server_name, ".test") | dedup server_name | fields ts, src, server_name | tail 3
