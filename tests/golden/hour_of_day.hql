# Off-hours activity per host (UTC hours 0-5).
conn | where hour(ts) < 6 | stats count() as off_hours by src | sort -off_hours, src | head 5
