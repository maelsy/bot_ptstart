import logging
import re
import os
import paramiko
import psycopg2

from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext
from dotenv import load_dotenv
from psycopg2 import Error

load_dotenv()

TOKEN = os.getenv('TOKEN')

# Подключаем логирование
logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)
# logging.disable(logging.INFO)

# Функция для комманды /start
def start(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /start - User:{user.full_name}')
    update.message.reply_text(
        f'Привет {user.full_name}!\nЧтобы посмотреть список доступных комманд введи /help')

# Функция для комманды /help
def helpCommand(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /help - User:{user.full_name}')
    update.message.reply_text(
        'Список доступных комманд:\n \
    /find_email - поиск email адресов в тексте\n \
    /find_phone_number - поиск телефонных номеров в\n\
    тексте\n\
    /verify_password - для проверки надежности пароля\n\
    /get_info_help - команды для сбора информации с Linux\n\
    системы\n\
    /get_db_help - команды для взаимодействия с базой данных\n')

# Функция для комманды /get_info_help
def getInfoHelp(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_info_help - User:{user.full_name}')
    update.message.reply_text(
        'Команды для сбора информации с Linux системы:\n\
    Сбор информации о системе:\n\
        /get_release - о релизе\n\
        /get_uname - об архитектуры процессора, имени хоста\n \
        системы и версии ядра\n\
        /get_uptime - о времени работы\n\
    /get_df - сбор информации о состоянии файловой системы\n\
    /get_free - сбор информации о состоянии оперативной\n\
    памяти\n\
    /get_mpstat - сбор информации о производительности\n\
    системы\n\
    /get_w - сбор информации о работающих в данной системе\n\
    пользователях\n\
    Сбор логов:\n\
        /get_auths -  последние 10 входов в систему\n\
        /get_critical -  последние 5 критических события\n\
    /get_ps - сбор информации о запущенных процессах\n\
    /get_ss - сбор информации об используемых портах\n\
    /get_apt_list - сбор информации об установленных пакетах\n\
    /get_services -  сбор информации о запущенных сервисах\n'
    )

# Функция для команды /get_db_help
def getDBHelp(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_db_help - User:{user.full_name}')
    update.message.reply_text('Команды для взаимодействия с базой данных:\n\
    /get_repl_logs - отображение логов репликаций\n\
    /get_email - вывод всех сохраненных Email адресов\n\
    /get_phone_numbers - вывод всех сохраненных телефонных номеров\n')

# Функция для комманды /find_phone_number
def findPhoneNumbersCommand(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /find_phone_number - User:{user.full_name}')
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')

    return 'find_phone_number'

# Функция для коммманды /find_email
def findEmailAddressCommand(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /find_email - User:{user.full_name}')
    update.message.reply_text('Введите текст для поиска Email адресов: ')

    return 'find_email'

# Функция для коммманды /verify_password
def passwordCheckerCommand(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /verify_password - User:{user.full_name}')
    update.message.reply_text('Введите пароль для проверки: ')

    return 'verify_password'

# Функция для поиска телефонных в тексте
def findPhoneNumbers(update: Update, context):

    logging.info('Function findPhoneNumbers start...')
    user_input = update.message.text
    phoneNumRegex = re.compile(
        r'(?:\+7|8)\s?[-(]?\d{3}[-)\s]?\s?\d{3}[-\s]?\d{2}[-\s]?\d{2}')
    phoneNumberList = phoneNumRegex.findall(user_input)
    context.user_data['phoneNumberList'] = phoneNumberList

    if not phoneNumberList:
        update.message.reply_text('Телефонные номера не найдены.')
        return ConversationHandler.END

    phoneNumbers = ''
    for i in range(len(phoneNumberList)):
        phoneNumbers += f'{i+1}. {phoneNumberList[i]}\n'

    update.message.reply_text(f'Найденные телефонные номера:\n{phoneNumbers}')
    update.message.reply_text(
        'Хотите сохранить найденные телефонные номер? - "да"/"нет"')
    logging.info('Function findPhoneNumbers completed successfully!')
    return 'save_phone_numbers'

# Функция для сохранения (или нет) найденный Email адресов
def savePhoneNumber(update: Update, context):

    logging.info('Function savePhoneNumber start...')
    user_input = update.message.text

    if user_input == 'да':
        phoneNumberList = context.user_data.get('phoneNumberList')
        sqlCommand = 'INSERT INTO phoneNumbers (phoneNumber) VALUES'
        values = [f"('{phone}')" for phone in phoneNumberList]
        sqlCommand += ' ' + ', '.join(values) + ';'
        dbQueryExec(update, context, sqlCommand, False)
        logging.info('Function savePhoneNumber completed succesfully!')
        return ConversationHandler.END
    else:
        logging.info('Function savePhoneNumber completed succesfully!')
        return ConversationHandler.END

# Функция для поиска Email адресов в тексте
def findEmailAddress(update: Update, context):

    logging.info('Function findEmailAddress start...')
    user_input = update.message.text
    emailAddressRegex = re.compile(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}')
    emailAddressList = emailAddressRegex.findall(user_input)
    context.user_data['emailAddressList'] = emailAddressList

    if not emailAddressList:
        update.message.reply_text('Email адреса не найдены.')
        return ConversationHandler.END

    emailAddresses = ''
    for i in range(len(emailAddressList)):
        emailAddresses += f'{i+1}. {emailAddressList[i]}\n'

    update.message.reply_text(
        f'Найденные адреса электронной почты:\n{emailAddresses}')
    update.message.reply_text(
        'Хотите сохранить найденные адреса? - "да"/"нет"')
    logging.info('Function findEmailAddress completed succesfully!')
    return 'save_email'

# Функция для сохранения (или нет) найденный Email адресов
def saveEmailAddress(update: Update, context):

    logging.info('Function saveEmailAddress start...')
    user_input = update.message.text

    if user_input == 'да':
        emailAddressList = context.user_data.get('emailAddressList')
        sqlCommand = 'INSERT INTO emails (email) VALUES'
        values = [f"('{email}')" for email in emailAddressList]
        sqlCommand += ' ' + ', '.join(values) + ';'
        dbQueryExec(update, context, sqlCommand, False)
        logging.info('Function saveEmailAddress completed succesfully!')
        return ConversationHandler.END
    else:
        logging.info('Function saveEmailAddress completed succesfully!')
        return ConversationHandler.END

# Функция для проверки сложности пароля
def passwordChecker(update: Update, context):

    logging.info('Function passwordChecker start...')
    user_input = update.message.text
    strongPasswordRegex = re.compile(
        r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$')

    if re.match(strongPasswordRegex, user_input):
        update.message.reply_text('Пароль сложный!')
        logging.info('Function passwordChecker completed succesfully!')
        return ConversationHandler.END
    else:
        update.message.reply_text('Пароль простой!\nТребования к паролю:\n \
        - Пароль должен содержать не менее восьми символов\n \
        - Пароль должен включать как минимум одну заглавную букву (A–Z)\n \
        - Пароль должен включать хотя бы одну строчную букву (a–z)\n \
        - Пароль должен включать хотя бы одну цифру (0–9)\n \
        - Пароль должен включать хотя бы один специальный символ, такой как !@#$%^&*()')
    logging.info('Function passwordChecker completed succesfully!')
    return ConversationHandler.END

# Функции для получения информации о системе
# Функция для получения информации о релизе
def getRelease(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_release - User:{user.full_name}')
    msg = getParam('lsb_release -a')
    update.message.reply_text(msg)

# Функция для получения информации об архитектуре процессора, имении хоста, и версии ядра
def getUname(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_uname - User:{user.full_name}')
    hostName = getParam('uname')
    arch = getParam('arch')
    kernelVersion = getParam('uname -r')
    update.message.reply_text(hostName)
    update.message.reply_text(arch)
    update.message.reply_text(kernelVersion)

# Функция для получения информации о времени работы
def getUptime(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_uptime - User:{user.full_name}')
    msg = getParam('uptime')
    update.message.reply_text(msg)

# Функция для получения информации о файловой системе
def getDf(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_df - User:{user.full_name}')
    msg = getParam('df -h')
    update.message.reply_text(msg)

# Функция для получения информации о состоянии оперативной памяти
def getFree(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_free - User:{user.full_name}')
    msg = getParam('free -h')
    update.message.reply_text(msg)

# Функция для получения информации о производительности системы
def getMpstat(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_mpstat - User:{user.full_name}')
    msg = getParam('mpstat')
    update.message.reply_text(msg)

# Функция для получения информации о работающих в данной системе пользователях
def getW(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_w - User:{user.full_name}')
    msg = getParam('w -s')
    update.message.reply_text(msg)

# Функция для получения информации о последних 10 входов в систему
def getAuths(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_auths - User:{user.full_name}')
    msg = getParam('last -n10 -R')
    update.message.reply_text(msg)

# Функция для получения информации о последних 5 критических событиях
def getCritical(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_critical - User:{user.full_name}')
    msg = getParam('journalctl -p crit -n5')
    update.message.reply_text(msg)

# Функция для получения информации о запущенных процессах
def getPs(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_ps - User:{user.full_name}')
    msg = getParam('ps -h')
    update.message.reply_text(msg)

# Функция для получения информации об используемых портах
def getSs(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_ss - User:{user.full_name}')
    msg = getParam('ss | tail -n10')
    update.message.reply_text(msg)

# Функция для начала работы с коммандой /get_apt_list
def getAptListCommand(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_apt_list - User:{user.full_name}')
    update.message.reply_text('Выберите режим поиска:\n\
    1. Вывод всех пакетов...\n\
    2. Вывод информации о конкретном пакете...\n')
    return 'get_apt'

# Функция для обработки сценариев команды /get_apt_list
def getAptList(update: Update, context):

    logging.info('Function getAptList for first scenario start...')
    user_input = update.message.text

    if user_input == '1':
        msg = getParam('apt list | tail -n 10')
        update.message.reply_text(msg)
    elif user_input == '2':
        update.message.reply_text('Название пакета:')
        return 'get_apt_by_name'
    else:
        update.message.reply_text('Неправильный ввод!')

    logging.info(
        'Function getAptList for first scenario completed succesfully!')
    return ConversationHandler.END

# Фунция для обработки 2 сценария команды /get_apt_list
def getAptByName(update: Update, context):

    logging.info('Function getAptByName for second scenario start...')
    packageName = update.message.text
    command = f'apt list --installed | grep {packageName} | tail -n 10'
    msg = getParam(command)
    update.message.reply_text(msg)
    logging.info('Function getAptByName for second scenario completed succesfully!')
    return ConversationHandler.END

# Функция для получения информации о запущенных сервисах
def getServices(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_services - User:{user.full_name}')
    msg = getParam('systemctl --all | tail -n 10')
    update.message.reply_text(msg)

# Функция для получения логов репликации
def getReplicaLogs(update: Update, context):
    user = update.effective_user
    logging.info(f'Calling command /get_repl_logs - User:{user.full_name}')
    msg = getParam('docker logs db_repl_image')
    update.message.reply_text(msg)

# Функция для подключения к Linux системе и получаения параметров
def getParam(commandName, host=os.getenv('RM_HOST'), port=os.getenv('RM_PORT'), username=os.getenv('RM_USER'),
             password=os.getenv('RM_PASSWORD')):

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username,
                   password=password, port=port)
    stdin, stdout, stderr = client.exec_command(commandName)
    data = stdout.read().decode('utf-8')
    error =stderr.read().decode('utf-8')
    client.close()
    return data, error

# Функция для подключения и выполнения запроса БД
def dbQueryExec(update: Update, context, SQLCommand, Type=True):
    connection = None
    try:
        connection = psycopg2.connect(user=os.getenv('DB_USER'),
                                      password=os.getenv('DB_PASSWORD'),
                                      host=os.getenv('DB_HOST'),
                                      port=os.getenv('DB_PORT'),
                                      database=os.getenv('DB_DATABASE'))
        cursor = connection.cursor()
        cursor.execute(SQLCommand)
        if Type:
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
            update.message.reply_text("Данные успешно записаны в базу.")
            logging.info("Команда успешно выполнена")
    except (Exception, Error) as error:
        logging.error("Ошибка при работе с PostgreSQL: %s", error)
    finally:
        if connection is not None:
            cursor.close()
            connection.close()
            logging.info("Соединение с PostgreSQL закрыто")

# Функция для команды /get_email
def getEmails(update: Update, context):
    sqlCommand = "SELECT * FROM emails;"
    dbQueryExec(update, context, sqlCommand)

# Функция для команды /get_phone_number
def getPhoneNumbers(update: Update, context):
    sqlCommand = "SELECT * FROM phoneNumbers;"
    dbQueryExec(update, context, sqlCommand)

# Echo функция
def echo(update: Update, context):
    user = update.effective_user
    logging.info(f'Echo - User:{user.full_name}')
    update.message.reply_text(update.message.text)


def main():

    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler(
            'find_phone_number', findPhoneNumbersCommand)],
        states={
            'find_phone_number': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
            'save_phone_numbers': [MessageHandler(Filters.text & ~Filters.command, savePhoneNumber)],
        },
        fallbacks=[]
    )

    convHandlerFindEmailAddress = ConversationHandler(
        entry_points=[CommandHandler('find_email', findEmailAddressCommand)],
        states={
            'find_email': [MessageHandler(Filters.text & ~Filters.command, findEmailAddress)],
            'save_email': [MessageHandler(Filters.text & ~Filters.command, saveEmailAddress)],
        },
        fallbacks=[]
    )

    convHandlerPasswordChecker = ConversationHandler(
        entry_points=[CommandHandler(
            'verify_password', passwordCheckerCommand)],
        states={
            'verify_password': [MessageHandler(Filters.text & ~Filters.command, passwordChecker)],
        },
        fallbacks=[]
    )

    convHandlerAptList = ConversationHandler(
        entry_points=[CommandHandler(
            'get_apt_list', getAptListCommand)],
        states={
            'get_apt': [MessageHandler(Filters.text & ~Filters.command, getAptList)],
            'get_apt_by_name': [MessageHandler(Filters.text & ~Filters.command, getAptByName)],
        },
        fallbacks=[]
    )

    dp.add_handler(CommandHandler('start', start))
    dp.add_handler(CommandHandler('help', helpCommand))
    dp.add_handler(CommandHandler('get_info_help', getInfoHelp))
    dp.add_handler(CommandHandler('get_db_help', getDBHelp))
    dp.add_handler(CommandHandler('get_release', getRelease))
    dp.add_handler(CommandHandler('get_uname', getUname))
    dp.add_handler(CommandHandler('get_uptime', getUptime))
    dp.add_handler(CommandHandler('get_df', getDf))
    dp.add_handler(CommandHandler('get_free', getFree))
    dp.add_handler(CommandHandler('get_mpstat', getMpstat))
    dp.add_handler(CommandHandler('get_w', getW))
    dp.add_handler(CommandHandler('get_auths', getAuths))
    dp.add_handler(CommandHandler('get_critical', getCritical))
    dp.add_handler(CommandHandler('get_ps', getPs))
    dp.add_handler(CommandHandler('get_ss', getSs))
    dp.add_handler(CommandHandler('get_services', getServices))
    dp.add_handler(CommandHandler('get_repl_logs', getReplicaLogs))
    dp.add_handler(CommandHandler('get_email', getEmails))
    dp.add_handler(CommandHandler('get_phone_numbers', getPhoneNumbers))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmailAddress)
    dp.add_handler(convHandlerPasswordChecker)
    dp.add_handler(convHandlerAptList)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    updater.start_polling()

    updater.idle()

if __name__ == '__main__':
    main()
