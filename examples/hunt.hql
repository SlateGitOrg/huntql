# A threat-hunting session over the bundled synthetic Zeek logs.
# Run with:  huntql -d fixtures/demo run examples/hunt.hql

# 1. Who talks the most over TLS?
conn | where dport == 443 | stats count() as conns, sum(orig_bytes) as sent by src
     | sort -conns | head 5;

# 2. Periodic check-ins (C2 beaconing), default threshold.
conn | beacon;

# 3. Stack JA3 client fingerprints: the long tail is where implants hide.
ssl | stack ja3;

# 4. User agents seen on the fewest hosts.
http | rare user_agent by src limit=3;

# 5. Who resolved a burst of never-before-seen, high-entropy names?
dns | first_seen src, query baseline=6h
    | eval e = entropy(query)
    | stats count() as new_names, avg(e) as entropy by src
    | sort -new_names | head 3;

# 6. Drill into the top beacon candidate's HTTP/TLS metadata.
ssl | where dst == 203.0.113.202 | stats count(), first(server_name) as sni, dc(ja3) as fingerprints by src, dst
