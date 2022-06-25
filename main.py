import csv
import requests
import json
import telebot

bot = telebot.TeleBot('')  # указать токен своего бота (https://web.telegram.org/k/#@BotFather создать и получить свой токен бота тут)

API_KEY = ""  # указать свой apiKey для доступа к nist (https://nvd.nist.gov/developers/request-an-api-key)
MAX_RESULTS = 50

fstec = []


def load_fstec(file):  ###Чтение файла с базой уязвимости с сайта ФСТЭК в формате CSV.
    with open(file, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter="\t", quotechar="\"")
        for row in reader:
            fstec.append(row)
        print("База ФСТЭК России загружена")


def search_fstec_id(id):
    for row in fstec:
        if (id in (row[0]).lower()) | (id in (row[18]).lower()):
            info = ""
            info += row[0] + " " + "(" + row[18] + ")\n"
            info += "Наименование уязвимости: " + row[1] + "\n"
            info += "Описание уязвимости: " + row[2] + "\n"
            info += "Вендор ПО: " + row[3] + "\n"
            info += "Название ПО: " + row[4] + "\n"
            info += "Версия ПО: " + row[5] + "\n"
            info += "Наименование ОС и тип аппаратной платформы: " + row[7] + "\n"
            info += "Дата выявления: " + row[9] + "\n"
            info += "Уровень опасности уязвимости: " + row[12] + "\n"
            info += "Возможные меры по устранению: " + row[13] + "\n"
            info += "Статус уязвимости: " + row[14] + "\n"
            info += "Информация об устранении: " + row[15] + "\n"
            info += "Ссылки на источники: " + row[17] + "\n"
            info += "Описание ошибки CWE: " + row[20] + "\n"
            return info
    return "Нет данных в базе ФСТЭК"


def search_fstec(search):
    info = ""
    d = 0
    for row in fstec:
        if search.lower() in (row[4]).lower():
            d += 1
            info += row[0] + " " + "(" + row[18] + ") "
            info += row[12].replace("уровень опасности (базовая оценка CVSS 2.0 составляет ", "").replace(")",
                                                                                                          "").replace(
                " уровень опасности (базовая оценка CVSS 3.0 составляет", "") + "\n"
        if d > MAX_RESULTS:
            break
    if info == '':
        return "Нет данных в базе ФСТЭК."
    return info


load_fstec("fstec.csv")


def search_nist(s):
    api = "https://services.nvd.nist.gov/rest/json/cves/1.0?apiKey=" + API_KEY + "&resultsPerPage=" + str(
        MAX_RESULTS) + "&keyword=" + s
    result_api = requests.get(api)  ###   Обращение к публичноу REST API и получаем ответ в формате json.
    if result_api.status_code == 200:
        j = json.loads(result_api.text)
        vulns = j['result']['CVE_Items']
        rinfo = "Найдено результатов в базе NIST: " + str(j['totalResults'])
        if int(j['totalResults']) > MAX_RESULTS:
            rinfo += ". Отображено: " + str(MAX_RESULTS)
        rinfo += "\n"
        for v in vulns:
            num = v['cve']['CVE_data_meta']['ID']
            rinfo = rinfo + num
            if 'baseMetricV3' in v['impact']:
                attackVector = v['impact']['baseMetricV3']['cvssV3']['attackVector']
                baseScore = v['impact']['baseMetricV3']['cvssV3']['baseScore']
                baseSeverity = v['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                rinfo = rinfo + ' ' + attackVector + ' ' + baseSeverity + ' ' + str(baseScore)
            rinfo += "\n"
    else:
        rinfo = "Не найдено в базе NIST." + result_api.status_code
    if rinfo == "":
        rinfo = "Не найдено в базе NIST."
    return rinfo


def search_nist_cve(s):
    api = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + s + "?apiKey=" + API_KEY
    result_api = requests.get(api)
    if result_api.status_code == 200:
        j = json.loads(result_api.text)
        vulns = j['result']['CVE_Items']
        rinfo = ""
        for v in vulns:
            num = v['cve']['CVE_data_meta']['ID']
            rinfo = rinfo + num
            if 'baseMetricV3' in v['impact']:
                attackVector = v['impact']['baseMetricV3']['cvssV3']['attackVector']
                baseScore = v['impact']['baseMetricV3']['cvssV3']['baseScore']
                baseSeverity = v['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                rinfo += ' ' + attackVector + ' ' + baseSeverity + ' ' + str(baseScore) + "\n\n"
            publishedDate = v['publishedDate']
            rinfo += "ДАТА ОБНАРУЖЕНИЯ: " + publishedDate + "\n\n"
            description = v['cve']['description']['description_data'][0]['value']
            rinfo += description + "\n\n"

            urls = v['cve']['references']['reference_data']
            for u in urls:
                rinfo += "Ссылки на источники: " + "\n" + u['url'] + " " + str(u['tags']) + "\n"
    else:
        rinfo = "Не найдено в базе NIST."
    if rinfo == "":
        rinfo = "Не найдено в базе NIST."
    return rinfo


@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(message.chat.id,
                     "Добро пожаловать в бот по поиску уязвимостей. Для получения руководства по боту введите /help.")


@bot.message_handler(commands=['help'])
def start(message):
    bot.send_message(message.from_user.id,
                     "Необходимо ввести поисковый запрос для получения списка уязвимостей или номер уязвимости. Например: android; CVE_2022-31069.")


@bot.message_handler()
def start(message):
    search = message.text.lower()
    print(search)
    if 'cve' in search or 'bdu' in search:
        res = search_nist_cve(search)
        bot.send_message(message.from_user.id, res)
        res = search_fstec_id(search)
        bot.send_message(message.from_user.id, res)
    else:
        res = search_nist(search) + "\n\n"
        bot.send_message(message.from_user.id, res)
        res = "Результаты поиска по базе ФСТЭК: \n" + search_fstec(search)
        bot.send_message(message.from_user.id, res)


bot.polling(none_stop=True, interval=0)
print("stop")
