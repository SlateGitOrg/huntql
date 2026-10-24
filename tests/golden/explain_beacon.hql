# explain
conn | where not is_private(dst) | beacon min_count=20
