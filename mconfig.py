#coding=UTF8
## Общие настройки программы
# IP-адрес интерфейса, на котором будет работать демон
interface_ip = ""
# UDP-порт для syslog-сообщений
sysport      = 7514
# UDP-порт для snmptrap-сообщений
macport      = 162
# Лог-файл для syslog
logsys   = "/var/log/maXys/syslog.log"
# Лог-файл для mactrap
logmac   = "/var/log/maXys/mactrap.log"
# Лог-файл демона
logmaXys = "/var/log/maXys/maXys.log"
# Интервал, через который данные об оборудовании будут обновляться
interval = 120

## Настройки для MySQL-сервера, откуда будет забираться список устройств
# (Адрес, пользователь, пароль, база данных, запрос, возвращающий <ip>,<id>)
mysql_addr  = "mysql.localhost"
mysql_user  = "user"
mysql_pass  = "password"
mysql_base  = "base"
mysql_query = "SELECT ip, id FROM devices;"

## Настройки для MySQL-сервер, куда будет сохраняться результат
# (Адрес, пользователь, пароль, база данных, таблица для syslog, таблица для mactrap)
mysql_addr_w = "mysql2.powernet"
mysql_user_w = "macsys"
mysql_pass_w = "macsyspassword"
mysql_base_w = "maxys"
mysql_stbl_w = "syslog"
mysql_mtbl_w = "mactrap"

## Настройки для Oracle APEX, куда будет отправляться результат через вызов URL
# Начало URL для mactrap
apex_m_url   = "http://oracledb.localhost:8082/apex/f?p=ins:1:::::QUERY:"
apex_m_query = "INSERT INTO c##table.mactrap (DATETIME,SWITCH_ID,IP,PORT,MAC,ACTION) "
# Начало URL для syslog
apex_s_url   = "http://oracledb.localhost:8082/apex/f?p=ins:1:::::QUERY:"
apex_s_query = "INSERT INTO c##table.syslog (DATETIME,SWITCH_ID,IP,TYPE_,DATA) "

## Настройки логирования
# Записывать ли данные в log?
write_to_log    = False
# Записывать ли данные в MySQL?
write_to_mysql  = False
# Записывать ли данные в Oracle?
write_to_oracle = True
# Сколько данных отправлять в базу за один раз. Данные отправляются 'пачкой' при достижении этого значения
max_chain     = 50
# Через этот интервал данные все равно будут отправлены, даже если не достигнуто максимальное кол-во записей
chain_timeout = 10

## Настройки Jabber
useJabber = True
jid = "maxys@jabber.localhost"
jps = "password"
jcr = "nebula@conference.jabber.localhost"
jnn = "maXys"

## Список слов для генерации уведомлений в Jabber
# Если слова из первого списка найдены в строке syslog, то эта строка будет передана в jabber
# Если слова из второго списка найдены в той же строке, то эта строка не будет передана в jabber
systojab_inc = ['execute', 'failed']
systojab_exc = ['noc:']