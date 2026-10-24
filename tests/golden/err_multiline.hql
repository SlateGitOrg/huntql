# Errors on later lines point at the right line and column.
conn
| where dport == 443
| stats count() by src
| sort -cnt
