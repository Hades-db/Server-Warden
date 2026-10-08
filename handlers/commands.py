import os
import socket
import time
from datetime import timedelta
import ipaddress

import docker
import psutil
from aiogram import F, Router
from aiogram.filters import CommandStart
from aiogram.types import Message
from keyboards.reply import get_main_keyboard

router = Router()

@router.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer(
        text="👋 <b>Приветствую, Хозяин!</b>\n"
             "Сервер под полным контролем. Используйте кнопки ниже для ручной проверки.",
        reply_markup=get_main_keyboard(),
        parse_mode="HTML"
    )


@router.message((F.text == "🔄 Проверить Docker"))
async def cmd_status(message: Message):
    status_msg = await message.answer("🔄 Связываюсь с Docker-сокетом, подождите...")
    
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        
        if not containers:
            await status_msg.edit_text("📭 На сервере пока нет ни одного запущенного контейнера.")
            return
            
        report = "📋 <b>Текущий статус контейнеров:</b>\n\n"
        
        for container in containers:
            name = container.name
            status = container.status
            
            status_emoji = "🟢" if status == "running" else "🔴"
            
            report += f"{status_emoji} <code>{name}</code> — <i>{status}</i>\n"

        await status_msg.edit_text(text=report, parse_mode="HTML")
        
    except Exception as e:
        await status_msg.edit_text(f"❌ <b>Не удалось получить данные от Docker:</b>\n<code>{e}</code>")


@router.message(F.text == "🖥️ Статус сервера")
async def cmd_server_status(message: Message):
    status_msg = await message.answer("📊 Опрашиваю датчики системы...")
    
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_string = str(timedelta(seconds=int(uptime_seconds)))

        cpu_usage = psutil.cpu_percent(interval=0.5)

        ram = psutil.virtual_memory()
        ram_total = round(ram.total / (1024 ** 3), 1)
        ram_used = round(ram.used / (1024 ** 3), 1)
        ram_percent = ram.percent

        disk_root = psutil.disk_usage('/')
        disk_root_total = round(disk_root.total / (1024 ** 3), 1)
        disk_root_used = round(disk_root.used / (1024 ** 3), 1)
        disk_root_percent = disk_root.percent

        disk_d = psutil.disk_usage('/D-huin9')
        disk_d_total = round(disk_d.total / (1024 ** 3), 1)
        disk_d_used = round(disk_d.used / (1024 ** 3), 1)
        disk_d_percent = disk_d.percent

        report = (
            f"🖥️ <b>Статус сервера:</b>\n\n"
            f"⏱️ <b>Время работы (Uptime):</b>\n<code>{uptime_string}</code>\n\n"
            f"🧠 <b>Загрузка CPU:</b> <code>{cpu_usage}%</code>\n\n"
            f"💾 <b>Оперативная память (RAM):</b>\n"
            f" ├ Занято: <code>{ram_used} ГБ</code> из <code>{ram_total} ГБ</code>\n"
            f" └ Нагрузка: <code>{ram_percent}%</code>\n\n"
            f"💽 <b>Системный диск (/):</b>\n"
            f" ├ Занято: <code>{disk_root_used} ГБ</code> из <code>{disk_root_total} ГБ</code>\n"
            f" └ Заполнено: <code>{disk_root_percent}%</code>"
        )

        await status_msg.edit_text(text=report, parse_mode="HTML")
      
    except Exception as e:
        await status_msg.edit_text(f"❌ <b>Не удалось собрать метрики сервера:</b>\n<code>{e}</code>")


def is_private_ip(ip_str: str) -> bool:
    if ip_str in ['127.0.0.1', '::1', 'localhost']:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


@router.message(F.text == "🛡️ Аудит безопасности")
async def cmd_security_audit(message: Message):
    status_msg = await message.answer("🔍 Сканирую систему и анализирую открытые порты...")
    
    try:
        connections = psutil.net_connections(kind='inet')
        
        try:
            docker_client = docker.from_env()
            containers = docker_client.containers.list(all=True)
        except Exception:
            containers = []

        aggregated_ports = {}
        
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN or conn.type == socket.SOCK_DGRAM:
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                ip = conn.laddr.ip
                port = conn.laddr.port
                pid = conn.pid
                
                proc_name = "Неизвестно"
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Доступ ограничен"

                if proc_name == "docker-proxy" and containers:
                    for container in containers:
                        port_bindings = container.attrs.get('HostConfig', {}).get('PortBindings') or {}
                        for c_port, host_bindings in port_bindings.items():
                            if host_bindings:
                                for binding in host_bindings:
                                    if int(binding.get('HostPort', 0)) == port:
                                        proc_name = f"Docker: {container.name}"

                key = (port, proto)
                if key not in aggregated_ports:
                    aggregated_ports[key] = {
                        "port": port,
                        "proto": proto,
                        "interfaces": set(),
                        "proc": proc_name,
                        "pid": pid or "—"
                    }
                aggregated_ports[key]["interfaces"].add(ip)

        if not aggregated_ports:
            await status_msg.edit_text("🛡️ <b>Аудит безопасности завершен.</b>\n\nНе найдено открытых портов.", parse_mode="HTML")
            return

        sorted_ports = sorted(aggregated_ports.values(), key=lambda x: x['port'])
        
        report = "🛡️ <b>Результаты сканирования портов сервера:</b>\n\n"
        
        warnings_count = 0
        secure_ports_count = 0
        
        for p in sorted_ports:
            has_global = any(ip in ['0.0.0.0', '::', ''] for ip in p['interfaces'])
            has_only_private = all(is_private_ip(ip) for ip in p['interfaces']) and not has_global

            if has_only_private:
                secure_ports_count += 1
                continue


            warnings_count += 1
            if has_global:
                security_status = "🔴 Глобальный (Внимание!)"
                if p['port'] == 22:
                    recommendation = "Доступ по SSH торчит наружу. Проверьте, что вход по паролю отключен (только ключи)."
                elif p['port'] == 80 or p['port'] == 443:
                    security_status = "🟡 Глобальный (Веб-сервер)"
                    recommendation = "Нормально для веб-трафика. Убедитесь в наличии SSL/HTTPS."
                elif p['port'] == 3306 or p['port'] == 5432 or p['port'] == 6379 or p['port'] == 27017:
                    security_status = "🚨 КРИТИЧЕСКИЙ (База Данных)"
                    recommendation = "Порт СУБД открыт для всего интернета! Срочно закройте его в UFW."
                else:
                    recommendation = "Порт открыт для внешнего мира. Убедитесь, что сервис защищен."
            else:
                security_status = "🟡 Смешанный/Внешний"
                recommendation = "Проверьте привязанные IP-адреса."

            interfaces_str = ", ".join(list(p['interfaces']))
            safe_proc = p['proc'].replace("<", "&lt;").replace(">", "&gt;")

            report += (
                f"🔌 <b>Порт:</b> <code>{p['port']}</code> ({p['proto']})\n"
                f" ├ 📦 <b>Процесс:</b> <code>{safe_proc}</code> (PID: <code>{p['pid']}</code>)\n"
                f" ├ 🌐 <b>Интерфейсы:</b> <code>{interfaces_str}</code>\n"
                f" ├ 🛡️ <b>Защита:</b> {security_status}\n"
                f" └ 💡 <b>Инфо:</b> <i>{recommendation}</i>\n\n"
            )


        report += (
            f"ℹ️ <b>Сводка аудита:</b>\n"
            f" ├ ⚠️ Требуют внимания/открыты наружу: <b>{warnings_count}</b>\n"
            f" └ 🟢 Локальные/Безопасные порты (скрыты): <b>{secure_ports_count}</b>"
        )

        await status_msg.edit_text(text=report, parse_mode="HTML")

    except Exception as e:
        await status_msg.edit_text(f"❌ <b>Не удалось провести сканирование системы:</b>\n<code>{e}</code>", parse_mode="HTML")