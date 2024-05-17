import logging
import re
import os
import paramiko
import psycopg2
import subprocess

from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext
from dotenv import load_dotenv
from psycopg2 import Error

load_dotenv()

TOKEN = os.getenv('TOKEN')

logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)

def start(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /start - User:{user.full_name}')
    update.message.reply_text(
        f'Привет {user.full_name}!\nЧтобы посмотреть список доступных комманд введи /help')

def help_command(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /help - User:{user.full_name}')
    update.message.reply_text(
        'Список доступных комманд:\n \
    /find_email - поиск email адресов в тексте\n \
    /find_phone_number - поиск телефонных номеров в тексте\n\
    /verify_password - для проверки надежности пароля\n\
    /get_info_help - команды для сбора информации с Linux системы\n\
    /get_db_help - команды для взаимодействия с базой данных\n')

def get_info_help(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_info_help - User:{user.full_name}')
    update.message.reply_text(
        'Команды для сбора информации с Linux системы:\n\
    Сбор информации о системе:\n\
        /get_release - о релизе\n\
        /get_uname - об архитектуре процессора, имени хоста и версии ядра\n\
        /get_uptime - о времени работы\n\
    /get_df - сбор информации о состоянии файловой системы\n\
    /get_free - сбор информации о состоянии оперативной памяти\n\
    /get_mpstat - сбор информации о производительности системы\n\
    /get_w - сбор информации о работающих в системе пользователях\n\
    Сбор логов:\n\
        /get_auths - последние 10 входов в систему\n\
        /get_critical - последние 5 критических событий\n\
    /get_ps - сбор информации о запущенных процессах\n\
    /get_ss - сбор информации об используемых портах\n\
    /get_apt_list - сбор информации об установленных пакетах\n\
    /get_services - сбор информации о запущенных сервисах\n')

def get_db_help(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_db_help - User:{user.full_name}')
    update.message.reply_text('Команды для взаимодействия с базой данных:\n\
    /get_repl_logs - отображение логов репликаций\n\
    /get_email - вывод всех сохраненных Email адресов\n\
    /get_phone_numbers - вывод всех сохраненных телефонных номеров\n')

def find_phone_numbers_command(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /find_phone_number - User:{user.full_name}')
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    return 1

def find_email_address_command(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /find_email - User:{user.full_name}')
    update.message.reply_text('Введите текст для поиска Email адресов: ')
    return 2

def password_checker_command(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /verify_password - User:{user.full_name}')
    update.message.reply_text('Введите пароль для проверки: ')
    return 3

def find_phone_numbers(update: Update, context: CallbackContext): 
    logging.info('Function findPhoneNumbers start...')
    user_input = update.message.text
    phone_num_regex = re.compile(r'(?<!\d)(?:\+7|8)[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}(?!\d)')
    phone_number_list = phone_num_regex.findall(user_input)
    phone_number_list = list(set(phone_number_list))
    context.user_data['phoneNumberList'] = phone_number_list

    if not phone_number_list:
        update.message.reply_text('Телефонные номера не найдены.')
        return ConversationHandler.END

    phone_numbers = '\n'.join([f'{i+1}. {num}' for i, num in enumerate(phone_number_list)])
    update.message.reply_text(f'Найденные телефонные номера:\n{phone_numbers}')
    update.message.reply_text('Хотите сохранить найденные телефонные номера? - "да"/"нет"')
    logging.info('Function findPhoneNumbers completed successfully!')
    return 4

def save_phone_number(update: Update, context: CallbackContext):
    logging.info('Function savePhoneNumber start...')
    user_input = update.message.text.lower()

    if user_input == 'да':
        phone_number_list = context.user_data.get('phoneNumberList')
        sql_command = 'INSERT INTO phone_numbers (value) VALUES '
        values = [f"('{phone}')" for phone in phone_number_list]
        sql_command += ', '.join(values) + ';'
        db_query_exec(update, context, sql_command, False)
        logging.info('Function savePhoneNumber completed successfully!')
        update.message.reply_text("Телефонные номера успешно сохранены.")
        return ConversationHandler.END
    else:
        logging.info('Function savePhoneNumber completed successfully!')
        update.message.reply_text("Телефонные номера не сохранены.")
        return ConversationHandler.END

def find_email_address(update: Update, context: CallbackContext):
    logging.info('Function findEmailAddress start...')
    user_input = update.message.text
    email_address_regex = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}')
    email_address_list = email_address_regex.findall(user_input)
    email_address_list = list(set(email_address_list))
    context.user_data['emailAddressList'] = email_address_list

    if not email_address_list:
        update.message.reply_text('Email адреса не найдены.')
        return ConversationHandler.END

    email_addresses = '\n'.join([f'{i+1}. {email}' for i, email in enumerate(email_address_list)])
    update.message.reply_text(f'Найденные адреса электронной почты:\n{email_addresses}')
    update.message.reply_text('Хотите сохранить найденные адреса? - "да"/"нет"')
    logging.info('Function findEmailAddress completed successfully!')
    return 5

def save_email_address(update: Update, context: CallbackContext):
    logging.info('Function saveEmailAddress start...')
    user_input = update.message.text.lower()

    if user_input == 'да':
        email_address_list = context.user_data.get('emailAddressList')
        sql_command = 'INSERT INTO emails (email) VALUES '
        values = [f"('{email}')" for email in email_address_list]
        sql_command += ', '.join(values) + ';'
        db_query_exec(update, context, sql_command, False)
        logging.info('Function saveEmailAddress completed successfully!')
        update.message.reply_text("Email адреса успешно сохранены.")
        return ConversationHandler.END
    else:
        logging.info('Function saveEmailAddress completed successfully!')
        update.message.reply_text("Email адреса не сохранены.")
        return ConversationHandler.END

def password_checker(update: Update, context: CallbackContext): 
    logging.info('Function passwordChecker start...')
    user_input = update.message.text
    strong_password_regex = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$')

    if re.match(strong_password_regex, user_input):
        update.message.reply_text('Пароль сложный!')
        logging.info('Function passwordChecker completed successfully!')
        return ConversationHandler.END
    else:
        update.message.reply_text('Пароль простой!\nТребования к паролю:\n \
        - Пароль должен содержать не менее восьми символов\n \
        - Пароль должен включать как минимум одну заглавную букву (A–Z)\n \
        - Пароль должен включать хотя бы одну строчную букву (a–z)\n \
        - Пароль должен включать хотя бы одну цифру (0–9)\n \
        - Пароль должен включать хотя бы один специальный символ, такой как !@#$%^&*()')
    logging.info('Function passwordChecker completed successfully!')
    return ConversationHandler.END

def get_release(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_release - User:{user.full_name}')
    msg, error = get_param('lsb_release -a')
    update.message.reply_text(msg or error)

def get_uname(update: Update, context: CallbackContext): 
    user = update.effective_user
    logging.info(f'Calling command /get_uname - User:{user.full_name}')
    host_name, _ = get_param('uname')
    arch, _ = get_param('arch')
    kernel_version, _ = get_param('uname -r')
    update.message.reply_text(host_name)
    update.message.reply_text(arch)
    update.message.reply_text(kernel_version)

def get_uptime(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_uptime - User:{user.full_name}')
    msg, error = get_param('uptime')
    update.message.reply_text(msg or error)

def get_df(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_df - User:{user.full_name}')
    msg, error = get_param('df -h')
    update.message.reply_text(msg or error)

def get_free(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_free - User:{user.full_name}')
    msg, error = get_param('free -h')
    update.message.reply_text(msg or error)

def get_mpstat(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_mpstat - User:{user.full_name}')
    msg, error = get_param('mpstat')
    update.message.reply_text(msg or error)

def get_w(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_w - User:{user.full_name}')
    msg, error = get_param('w -s')
    update.message.reply_text(msg or error)

def get_auths(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_auths - User:{user.full_name}')
    msg, error = get_param('last -n10 -R')
    update.message.reply_text(msg or error)

def get_critical(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_critical - User:{user.full_name}')
    msg, error = get_param('journalctl -p crit -n5')
    update.message.reply_text(msg or error)

def get_ps(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_ps - User:{user.full_name}')
    msg, error = get_param('ps -h')
    update.message.reply_text(msg or error)

def get_ss(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_ss - User:{user.full_name}')
    msg, error = get_param('ss -tulwn')
    update.message.reply_text(msg or error)

def get_apt_list_command(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_apt_list - User:{user.full_name}')
    update.message.reply_text('Выберите режим поиска:\n\
    1. Вывод всех пакетов...\n\
    2. Вывод информации о конкретном пакете...')
    return 6

def get_apt_list(update: Update, context: CallbackContext):
    logging.info('Function getAptList for first scenario start...')
    user_input = update.message.text

    if user_input == '1':
        msg, error = get_param('apt list --installed | head -n 10')
        update.message.reply_text(msg or error)
    elif user_input == '2':
        update.message.reply_text('Название пакета:')
        return 7
    else:
        update.message.reply_text('Неправильный ввод!')

    logging.info('Function getAptList for first scenario completed successfully!')
    return ConversationHandler.END

def get_apt_by_name(update: Update, context: CallbackContext): 
    logging.info('Function getAptByName for second scenario start...')
    package_name = update.message.text
    command = f'apt list --installed | grep {package_name} | tail -n 10'
    msg, error = get_param(command)
    update.message.reply_text(msg or error)
    logging.info('Function getAptByName for second scenario completed successfully!')
    return ConversationHandler.END

def get_services(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_services - User:{user.full_name}')
    msg, error = get_param('systemctl list-units --type=service | head -n 5')
    update.message.reply_text(msg or error)

def get_replica_logs(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Calling command /get_repl_logs - User:{user.full_name}')
    command = "cat /var/log/postgresql/postgresql.log | grep repl | tail -n 15"
    res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0 or res.stderr.decode():
        update.message.reply_text("Can not open log file!")
    else:
        update.message.reply_text(res.stdout.decode().strip('\n'))

def get_param(command_name, host=os.getenv('RM_HOST'), port=os.getenv('RM_PORT'), username=os.getenv('RM_USER'),
              password=os.getenv('RM_PASSWORD')):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password, port=port)
    stdin, stdout, stderr = client.exec_command(command_name)
    data = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    client.close()
    return data, error

def db_query_exec(update: Update, context: CallbackContext, sql_command: str, fetch: bool = True):
    connection = None
    try:
        connection = psycopg2.connect(user=os.getenv('DB_USER'),
                                      password=os.getenv('DB_PASSWORD'),
                                      host=os.getenv('DB_HOST'),
                                      port=os.getenv('DB_PORT'),
                                      database=os.getenv('DB_DATABASE'))
        cursor = connection.cursor()
        cursor.execute(sql_command)
        if fetch:
            data = cursor.fetchall()
            if data:
                for row in data:
                    update.message.reply_text(str(row))
                    logging.info("Команда успешно выполнена")
            else:
                update.message.reply_text(f"Таблица пуста")
                logging.info("Команда успешно выполнена")
        else:
            connection.commit()
            logging.info("Команда успешно выполнена")
    except (Exception, Error) as error:
        logging.error("Ошибка при работе с PostgreSQL: %s", error)
    finally:
        if connection is not None:
            cursor.close()
            connection.close()
            logging.info("Соединение с PostgreSQL закрыто")

def get_emails(update: Update, context: CallbackContext):
    sql_command = "SELECT * FROM emails;"
    db_query_exec(update, context, sql_command)

def get_phone_numbers(update: Update, context: CallbackContext):
    sql_command = "SELECT * FROM phone_numbers;"
    db_query_exec(update, context, sql_command)

def echo(update: Update, context: CallbackContext):
    user = update.effective_user
    logging.info(f'Echo - User:{user.full_name}')
    update.message.reply_text(update.message.text)

def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    conv_handler_find_phone_numbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_number', find_phone_numbers_command)],
        states={
            1: [MessageHandler(Filters.text & ~Filters.command, find_phone_numbers)],
            4: [MessageHandler(Filters.text & ~Filters.command, save_phone_number)],
        },
        fallbacks=[]
    )

    conv_handler_find_email_address = ConversationHandler(
        entry_points=[CommandHandler('find_email', find_email_address_command)],
        states={
            2: [MessageHandler(Filters.text & ~Filters.command, find_email_address)],
            5: [MessageHandler(Filters.text & ~Filters.command, save_email_address)],
        },
        fallbacks=[]
    )

    conv_handler_password_checker = ConversationHandler(
        entry_points=[CommandHandler('verify_password', password_checker_command)],
        states={
            3: [MessageHandler(Filters.text & ~Filters.command, password_checker)],
        },
        fallbacks=[]
    )

    conv_handler_apt_list = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={
            6: [MessageHandler(Filters.text & ~Filters.command, get_apt_list)],
            7: [MessageHandler(Filters.text & ~Filters.command, get_apt_by_name)],
        },
        fallbacks=[]
    )

    dp.add_handler(CommandHandler('start', start))
    dp.add_handler(CommandHandler('help', help_command))
    dp.add_handler(CommandHandler('get_info_help', get_info_help))
    dp.add_handler(CommandHandler('get_db_help', get_db_help))
    dp.add_handler(CommandHandler('get_release', get_release))
    dp.add_handler(CommandHandler('get_uname', get_uname))
    dp.add_handler(CommandHandler('get_uptime', get_uptime))
    dp.add_handler(CommandHandler('get_df', get_df))
    dp.add_handler(CommandHandler('get_free', get_free))
    dp.add_handler(CommandHandler('get_mpstat', get_mpstat))
    dp.add_handler(CommandHandler('get_w', get_w))
    dp.add_handler(CommandHandler('get_auths', get_auths))
    dp.add_handler(CommandHandler('get_critical', get_critical))
    dp.add_handler(CommandHandler('get_ps', get_ps))
    dp.add_handler(CommandHandler('get_ss', get_ss))
    dp.add_handler(CommandHandler('get_services', get_services))
    dp.add_handler(CommandHandler('get_repl_logs', get_replica_logs))
    dp.add_handler(CommandHandler('get_email', get_emails))
    dp.add_handler(CommandHandler('get_phone_numbers', get_phone_numbers))
    dp.add_handler(conv_handler_find_phone_numbers)
    dp.add_handler(conv_handler_find_email_address)
    dp.add_handler(conv_handler_password_checker)
    dp.add_handler(conv_handler_apt_list)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
