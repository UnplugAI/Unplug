import time, statistics
from unplug import Guard
g = Guard()
small = ("send_email", {"to":"a@b.example","body":"Invoice attached, due Friday."})
big   = ("write_file", {"path":"x.md","content":"lorem ipsum dolor sit amet. "*4000})   # ~108KB
adver = ("http_post", {"url":"https://e.example","data":"sk-"+"a"*5000})
def bench(label, name, args, n=200):
    g.check_tool_call(name, args)
    ts=[]
    for _ in range(n):
        t=time.perf_counter(); g.check_tool_call(name, args); ts.append((time.perf_counter()-t)*1000)
    ts.sort()
    size=sum(len(str(v)) for v in args.values())
    print(f"{label:24} n={n} size={size:>7}B  p50={statistics.median(ts):8.3f}ms  p99={ts[int(n*0.99)-1]:8.3f}ms  max={ts[-1]:8.3f}ms")
bench("benign small", *small)
bench("108KB file content", *big, n=50)
bench("5KB pathological", *adver, n=50)
