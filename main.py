import asyncio
from aiogram import Bot, Dispatcher
from config.config import BOT_TOKEN
from middlewares.auth import SecurityMiddleware
from handlers.commands import router as commands_router
from services.docker_mon import start_monitoring

async def main():
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    dp.message.outer_middleware(SecurityMiddleware())

    dp.include_router(commands_router)

    asyncio.create_task(start_monitoring(bot))

    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())

if __name__ == "__main__":
    asyncio.run(main())