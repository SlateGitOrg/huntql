conn
| where src in 10.20.1.0/28 and dport in [80, 8443] and not is_private(dst)
| stats count(), dc(dst) as peers by src, dport
| sort src, dport
