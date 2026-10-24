dns
| where rcode_name == "NXDOMAIN"
| eval e = entropy(query), labels = len(query)
| stats count(), avg(e) as avg_entropy, max(labels) as longest by src
