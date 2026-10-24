# Lower threshold and coarser grouping surface noisier channels too.
conn
| beacon min_score=0.35 min_count=12 by src, dst
| fields src, dst, count, period, jitter, acf, score
