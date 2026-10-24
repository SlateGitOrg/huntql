conn | rename src as client | eval kb = orig_bytes / 1024, long = duration > 5s | where long | stats count() as n, avg(kb) as avg_kb by client | sort -n | head 3
