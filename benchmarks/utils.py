import time
import statistics

def timeit(func):
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        end = time.perf_counter()
        return result, (end - start)
    return wrapper

def summarize(name, values):
    print(f"\n=== {name} ===")
    print(f"Runs: {len(values)}")
    print(f"Avg: {statistics.mean(values)*1000:.2f} ms")
    print(f"Min: {min(values)*1000:.2f} ms")
    print(f"Max: {max(values)*1000:.2f} ms")