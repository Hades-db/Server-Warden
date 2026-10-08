from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message
from config.config import ADMIN_ID

class SecurityMiddleware(BaseMiddleware):
    async def __call__(self, handler, event: TelegramObject, data: dict):
        if not isinstance(event, Message):
            return await handler(event, data)

        user_id = event.from_user.id
        if user_id != ADMIN_ID:
            bot = data.get("bot")
            if bot:
                try:
                    await bot.send_message(
                        chat_id=ADMIN_ID, 
                        text=f"🔔 **Кто-то чужой пишет твоему боту!**\n\n"
                             f"👤 **Имя:** {event.from_user.full_name}\n"
                             f"🤖 **Юзернейм:** @{event.from_user.username or 'отсутствует'}\n"
                             f"🆔 **ID пользователя:** `{user_id}`\n"
                             f"💬 **Что он написал:** *\"{event.text}\"*"
                    )
                except Exception:
                    pass
            return
        return await handler(event, data)