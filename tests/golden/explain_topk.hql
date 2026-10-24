# explain
conn | where dport == 443 | where proto == "tcp" | stats count() by src | sort -count | head 10
