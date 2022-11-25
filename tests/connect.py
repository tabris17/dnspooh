import asyncio
from pool import Pool

pool = Pool()

async def main():
    reader, writer = await pool.connect('https', '127.0.0.1')

asyncio.run(main())
