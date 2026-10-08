from aiogram.utils.keyboard import ReplyKeyboardBuilder
from aiogram.types import ReplyKeyboardMarkup

def get_main_keyboard() -> ReplyKeyboardMarkup:
    builder = ReplyKeyboardBuilder()

    builder.button(text="🔄 Проверить Docker")
    builder.button(text="🖥️ Статус сервера")
    builder.button(text="🛡️ Аудит безопасности")

    builder.adjust(2, 1)

    return builder.as_markup(
        resize_keyboard=True,
        input_field_placeholder="Выберите действие в меню..."
    )