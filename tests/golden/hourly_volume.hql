conn | eval hr = bin(ts, 2h) | stats count(), sum(orig_bytes) as bytes, avg(duration) as avg_dur by hr | sort hr
