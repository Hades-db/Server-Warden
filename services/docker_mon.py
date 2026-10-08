import asyncio
import socket
import ipaddress
import docker
import psutil
from config.config import ADMIN_ID, CHECK_INTERVAL
from aiogram import Bot

def is_private_ip(ip_str: str) -> bool:
    if ip_str in ['127.0.0.1', '::1', 'localhost']:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

async def run_background_security_audit(bot: Bot):
    try:
        connections = psutil.net_connections(kind='inet')
        critical_alerts = []

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN or conn.type == socket.SOCK_DGRAM:
                ip = conn.laddr.ip
                port = conn.laddr.port
                
                is_global = not is_private_ip(ip) and ip not in ['0.0.0.0', '::', '']
                if ip in ['0.0.0.0', '::', '']:
                    is_global = True

                if is_global and (port == 3306 or port == 5432 or port == 6379 or port == 27017):
                    pid = conn.pid
                    proc_name = "Неизвестно"
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                        except Exception:
                            proc_name = "Доступ ограничен"

                    critical_alerts.append(f"🚨 **Порт СУБД открыт в мир!**\n🔌 Порт: `{port}`\n📦 Процесс: `{proc_name}`\n🌐 Интерфейс: `{ip}`")

        if critical_alerts:
            report = "🛡️ **Фоновый аудит безопасности обнаружил критические уязвимости!**\n\n" + "\n\n".join(critical_alerts) + "\n\n💡 *Рекомендация:* Срочно закройте эти порты с помощью UFW или привяжите сервисы к 127.0.0.1."
            await bot.send_message(chat_id=ADMIN_ID, text=report, parse_mode="Markdown")

    except Exception:
        pass

async def start_monitoring(bot: Bot):
    try:
        client = docker.from_env()
    except Exception as e:
        try:
            await bot.send_message(
                chat_id=ADMIN_ID, 
                text=f"🚨 **Критическая ошибка!** Бот не может подключиться к Docker-сокету:\n`{e}`"
            )
        except Exception:
            pass
        return

    down_containers = set()
    
    seconds_in_day = 86400
    cycles_for_day = max(1, seconds_in_day // CHECK_INTERVAL)
    cycle_count = 0

    while True:
        try:
            containers = client.containers.list(all=True)
            for container in containers:
                name = container.name
                status = container.status

                if name.lower() == "serverwarden":
                    continue
        
                if status != "running":
                    if name not in down_containers:
                        down_containers.add(name)
                        text = f"❌ **Внимание! Контейнер упал!**\n📦 **Имя:** `{name}`\n📊 **Статус:** `{status}`"
                        await bot.send_message(chat_id=ADMIN_ID, text=text, parse_mode="Markdown")

                else:
                    if name in down_containers:
                        down_containers.remove(name)
                        
                        text = f"✅ **Контейнер снова в строю!**\n📦 **Имя:** `{name}`\n📊 **Статус:** ожил (`running`)"
                        await bot.send_message(chat_id=ADMIN_ID, text=text, parse_mode="Markdown")
                                    
        except Exception:
            pass

        cycle_count += 1
        if cycle_count >= cycles_for_day:
            cycle_count = 0
            asyncio.create_task(run_background_security_audit(bot))

        await asyncio.sleep(CHECK_INTERVAL)