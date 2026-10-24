dns | eval d = sld(query) | where rcode_name == "NOERROR" | stack d limit=5
