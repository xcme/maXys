**maXys** - сборщик MAC-notify с коммутаторов D-Link и Syslog-сообщений с любых других устройств в сети. Получаемые сообщения размещаются в базах данных MySQL/Oracle и log-файлах на диске. Поддерживается отправка уведомлений об определенных событиях в jabber-конференцию.

## Предназначение сервиса

Сетевые устройства могут быть настроены на отправку сообщений об возникающих событиях на внешние серверы в сети. Такие сообщения отправляются при помощи Syslog и SNMP-Trap. Сервис **maXys** выступает в роли Syslog-сервера, а также SNMP-менеджера (только для MAC-Notify SNMP-Trap коммутаторов D-Link). Он принимает такие сообщения и сохраняет их в базе данных или в log-файлах. Также сервис может выбирать из общей массы уведомлений конкретные события. Например, можно настроить **maXys** на отправку в jabber-конференцию уведомлений о неудачных попытках входа на коммутаторы.

## Возможности maXys

* Прием Syslog-сообщений от коммутаторов
* Прием и разбор MAC-notify сообщений от коммутаторов D-Link
* Сохранение данных в базах MySQL/Oracle и в log-файле
* Уведомление в конференцию jabber о заранее определенных событиях
* Использование ID коммутатора из базы данных, что позволяет сохранять историю коммутатора даже при смене его IP-адреса

## Особенности работы

* Работа системным сервисом (daemon) под Linux/FreeBSD
* Разбор MAC-notify сообщений только с одним MAC-адресом (по умолчанию коммутаторы D-Link присылают сообщения как раз с одним MAC-адресом в каждом SNMP Trap)
* Возможность параллельной работы с штатным сервисом Syslog (для **maXys** потребуется задать другой UDP-порт)

## Требования

* Операционная система Linux или FreeBSD
* Python2 с модулями MySQLdb, python-psycopg2 и xmpp
* Доступ к MySQL- или PostgreSQL-серверу (базе биллинга) для получения списка устройств

## Принцип работы

**maXys** запускается системным сервисом и периодически забирает из биллинга информацию о коммутаторах. Запрос должен вернуть таблицу вида:

ip         | id
-----------|----
10.90.90.95| 1
10.90.90.98| 2

После этого **maXys** начинает прослушивать порт для приема Syslog-сообщений (по умолчанию 7514) и порт для приема SNMP Trap (по умолчанию 162). При получении сообщений от коммутаторов сервис, в зависимости от настроек, сохраняет их в log-файл или отправляет в базу данных MySQL или Oracle. По IP-адресу коммутатора определяется его идентификатор в биллинге, в результате чего история коммутатора сохраняется даже в случае изменения его IP-адреса.

Через 2 минуты (по умолчанию) сервис перезапросит из биллинга информацию о коммутаторах и их ID актуализирует эти данные в своей памяти.

**Подсказка**: Не все сетевые устройства позволяют указывать порт на сервере Syslog. Чтобы обойти это ограничение, оставив при этом **maXys** на нестандартном порту, можно воспользоваться правилом для iptables:
```
-A PREROUTING -d <server_ip>/32 -i <if_name> -p udp -m udp --dport 514 -j DNAT --to-destination <server_ip>:7514
```

## Конфигурирование
### Описание параметров в файле mconfig.py

#### Общие настройки программы
Параметр        | Описание
----------------|---------
interface_ip    | IP-адрес интерфейса, на котором будет работать демон
sysport         | UDP-порт для syslog-сообщений
macport         | UDP-порт для snmptrap-сообщений
logsys          | Лог-файл для syslog
logmac          | Лог-файл для mactrap
logmaXys        | Лог-файл демона
log_size        | Размер файла журнала при достижении которого начинается ротация
log_backupcount | Количество архивных копий журнала
interval        | Интервал, через который данные об оборудовании будут обновляться

#### Настройки для MySQL-сервера, откуда будет забираться список устройств
Параметр      | Описание
--------------|---------
mysql_addr    | Адрес MySQL-сервера, откуда будет забираться список
mysql_user    | Имя пользователя
mysql_pass    | Пароль
mysql_base    | Имя базы данных

#### Настройки для PostgreSQL-сервера, откуда будет забираться список устройств
Параметр        | Описание
--------------- | --------
postgresql_addr | Адрес PostgreSQL-сервера, откуда будет забираться список
postgresql_user | Имя пользователя
postgresql_pass | Пароль
postgresql_base | Имя базы данных
use_postgresql  | Параметр, определяющий, использовать ли MySQL либо же PostgreSQL (когда установлен в *True*)

Параметр   | Описание
-----------|---------
db_query   | Запрос к базе данных для получения IP-адресов и ID устройств


#### Настройки для MySQL-сервера, куда будет сохраняться результат
   Параметр   | Описание
--------------|---------
mysql_addr_w  | Адрес MySQL-сервера для сохранения результатов
mysql_user_w  | Имя пользователя
mysql_pass_w  | Пароль
mysql_base_w  | Имя базы данных
mysql_stbl_w  | Имя таблицы syslog
mysql_mtbl_w  | Имя таблицы mactrap

#### Настройки для Oracle APEX*, куда будет отправляться результат через вызов URL
   Параметр   | Описание
--------------|---------
apex_m_url    | URL для Oracle APEX для отправки MAC-notify сообщений, например "http://oracledb.localhost:8082/apex/f?p=ins:1:::::QUERY:"
apex_m_query  | Начало запроса для APEX для MAC-notify сообщений, например "INSERT INTO c##table.mactrap (DATETIME,SWITCH_ID,IP,PORT,MAC,ACTION) "
apex_s_url    | URL для Oracle APEX для отправки Syslog сообщений, например "http://oracledb.localhost:8082/apex/f?p=ins:1:::::QUERY:"
apex_s_query  |  Начало запроса для APEX для Syslog сообщений, например "INSERT INTO c##table.syslog (DATETIME,SWITCH_ID,IP,TYPE_,DATA) "
\*Настройка Oracle APEX для работы с **maXys** не является частью данного руководства. Под FreeBSD нет нативных инструментов для работы с Oracle, поэтому **maXys** использует Oracle APEX как своеобразный "шлюз" к базе Oracle.

#### Настройки логирования
   Параметр     | Описание
----------------|---------
write_to_log    | Записывать ли данные в log?
write_to_mysql  | Записывать ли данные в MySQL?
write_to_oracle | Записывать ли данные в Oracle?
max_chain       | Сколько данных отправлять в базу за один раз. Данные отправляются 'пачкой' при достижении этого значения
chain_timeout   | Через этот интервал данные все равно будут отправлены, даже если не достигнуто максимальное кол-во записей

#### Настройки Jabber
Параметр  | Описание
----------|---------
useJabber | Параметр, определяющий будут ли события отправляться в Jabber
jid       | Jabber ID
jps       | Пароль к учетной записи Jabber
jcr       | Имя конференции Jabber
jnn       | Псевдоним для конференции Jabber

#### Список слов для генерации уведомлений в Jabber.
Параметр     | Описание
-------------| --------
systojab_inc | Если слова из этого списка найдены в строке syslog, то эта строка будет передана в jabber. Список задается в синтаксисе python, например "**['execute', 'failed']**".
systojab_exc | Если слова из этого списка найдены в той же строке, то эта строка не будет передана в jabber. Список задается в синтаксисе python, например "**['noc:']**".

## Установка под Linux (пример для Centos 7)
+ Выполните команду: **git clone https://github.com/xcme/maXys.git**
+ Скопируйте файл '**maxys.service**' из директории '*./linux/centos/*' в '*/etc/systemd/system/*'.
+ Создайте каталог /var/log/maXys
+ Запустите сервис командой **systemctl start maxys**.
+ Добавьте автозапуск сервиса при загрузке системы командой **systemctl enable maxys**.

## Установка под FreeBSD
+ Скопируйте файл **maXys** из директории '*freebsd*' в /usr/local/etc/rc.d/, а остальные файлы в /usr/local/etc/maXys/.
+ Создайте каталог /var/log/maXys
+ Добавьте строку **maXys_enable="YES"** в файл /etc/rc.conf.
+ Запустите сервис командой **service maXys start**.


## Настройка доступа к MySQL

Чтобы **maXys** мог отправлять данные в MySQL, на сервере MySQL нужно создать пользователя и базу данных с соответствующими таблицами. Для создания пользователя можно воспользоваться командами из файла *create_user.sql*, а для создания базы данных - командами файла *maxys.sql*. Тип таблиц и кодировку можно поставить на свой вкус, в этих файлах просто рабочий пример.

## Настройка коммутатора на примере D-Link

Чтобы коммутатор начал отправлять сообщения сервису **maXys** нужно воспользоваться командами:

    create syslog host 1 ipaddress <maXys_IP-address> udp_port 7514 state enable severity debug
    enable syslog

Для отправки MAC-notify уведомлений нужно ввести команды:

    config mac_notification ports 1-28 disable
    config mac_notification ports 1-24  enable
    create snmp host <maXys_IP-address> v2c <community-string>
    enable mac_notification

## Список изменений

### [4.1.24] - 2018.01.24

#### Добавлено
- Поддержка PostgreSQL в качестве источника данных
- Ротация логов

#### Изменено
- Исправлены некоторые опечатки в тексте
- Для каждого вывода в лог теперь определена его важность (severity)

### [2.6.23] - 2016.06.23

#### Добавлено
- Добавлен скрипт для запуска сервиса под Linux

#### Изменено
- Изменен принцип нумерации версий
- Некоторые косметические изменения кода

### [1.5.0] - 2015.10.12

Релиз версии 1.5.0
