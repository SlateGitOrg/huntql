# Which host suddenly resolves many never-before-seen names?
dns
| first_seen src, query baseline=6h
| stats count() as new_names, min(first_seen) as first by src
| sort -new_names
| head 3
