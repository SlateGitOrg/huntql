# data: json
conn | stats count(), sum(orig_bytes) as sent, min(ts), max(ts) by dport | sort dport
