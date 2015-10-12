#!/usr/local/bin/python2
#coding=UTF8
#version 1.5.0 (2015.10.12)

import sys, time, socket, struct, MySQLdb, urllib2, logging, xmpp
from daemon import Daemon
from mconfig import interface, sysport, macport, logsys, logmac, logmaXys
from mconfig import mysql_addr, mysql_user, mysql_pass, mysql_base, mysql_query
from mconfig import mysql_addr_w, mysql_user_w, mysql_pass_w, mysql_base_w
from mconfig import mysql_stbl_w, mysql_mtbl_w, apex_m_url, apex_s_url
from mconfig import apex_m_query, apex_s_query, write_to_log, write_to_mysql
from mconfig import write_to_oracle, max_chain, chain_timeout, interval
from mconfig import useJabber, jid, jps, jcr, jnn, systojab_inc, systojab_exc

# ------- Настройка системы логирования  -------

# В этом блоке настраиваем logger'ы, чтобы писать логи в разные файлы
# Всего делаем 3 logger'а для syslog (s), mactrap (m) и maXys (x)
formatter_s = logging.Formatter('%(asctime)s %(message)s')
formatter_m = logging.Formatter('%(asctime)s %(message)s')
formatter_x = logging.Formatter('%(asctime)s %(message)s')

log_s = logging.FileHandler(logsys)
log_m = logging.FileHandler(logmac)
log_x = logging.FileHandler(logmaXys)

log_s.setFormatter(formatter_s)
log_m.setFormatter(formatter_m)
log_x.setFormatter(formatter_x)

slogger=logging.getLogger('s')
mlogger=logging.getLogger('m')
xlogger=logging.getLogger('x')

slogger.setLevel(logging.INFO)
mlogger.setLevel(logging.INFO)
xlogger.setLevel(logging.INFO)

slogger.addHandler(log_s)
mlogger.addHandler(log_m)
xlogger.addHandler(log_x)

# ------- Конец настройки системы логирования  -------


# ------- Начало блока функций  -------

# Функция для преобразования строки символов в hex-string
def ByteToHex(byteStr):
    return ''.join( [ "%02X " % ord( x[0:1] ) for x in byteStr ] ).split()

# Функция преобразования IP в LongIP
def IP2Long(ip_addr):
    return struct.unpack("!L", socket.inet_aton(ip_addr))[0]

# Функция, получающая из строки символов тип операции, MAC-адрес и порт
def MT_Prepare_Data(macdata):
    mt_act = ''; mt_mac = ''; mt_port = '';
    # Преобразовываем символы в hex-string
    macdata = ByteToHex(macdata[-12:])
    # Если на определенном месте найден нужный признак, получаем искомые данные:
    # Дополнительно делаем проверку на 'битый' пакет. Если ожидаемых данных нет, ничего не произойдет
    try:
	if macdata[0]+macdata[1] == '040A':
	    mt_act  = int(macdata[2],10)    # - 'Действие' (или тип события). Бывает Add(1), Remove(2) и Move(3)
	    mt_mac  = ''.join(macdata[3:9]) # - MAC-адрес
	    mt_port = int(macdata[10],16)   # - Номер порта
    except:
	pass
    # Если 'Действие' в ожидаемом диапазоне, длина MAC-адреса равна 12 и порт определен, возвращаем эти данные
    if (mt_act in [1, 2, 3]) & (len(mt_mac)==12) & (mt_port!=''):
        return mt_act, mt_mac, mt_port
    # Если же найдено что-то непонятное, возвращаем 'False' во всех случаях
    else:
        return False, False, False

# Функция, определяющая тип события и обрезающая спецсимволы вида '<130>'
def SL_Prepare_Data(sysdata):
    sl_type = ""; sl_data = '';
    # Обрезаем спецсимволы в начале строки
    if sysdata[0:3] == '<13': sl_data = sysdata[5:]
    if ('INFO:' in sl_data) & (sl_type == ''): sl_type = 1 # - Тип 'INFO'
    if ('WARN:' in sl_data) & (sl_type == ''): sl_type = 2 # - Тип 'WARN'
    if ('CRIT:' in sl_data) & (sl_type == ''): sl_type = 3 # - Тип 'CRIT'
    # Если тип в ожидаемом диапазоне и данные не пусты, возвращаем тип и данные, обрезая данные до 250 символов
    if (sl_type in [1, 2, 3]) & (sl_data != ''):
	return sl_type, sl_data[0:250]
    # Если же найдено что-то непонятное, возвращаем 'False' во всех случаях
    else:
	return False, False

# Функция для получения списка устройств из базы MySQL
def GetDevicesFromMySQL():
    # Пробуем подключиться к базе данных MySQL. Используем таймаут в 2 секунды
    try:
	mysql_db = MySQLdb.connect(host=mysql_addr, user=mysql_user, passwd=mysql_pass, db=mysql_base, connect_timeout=2)
    # Если возникла ошибка при подключении пишем в лог об ошибке и возвращаем пустой массив
    except MySQLdb.Error as err:
	xlogger.info("MySQL Error ('%s'): %s",mysql_addr,err.args[1])
	return {'0':0}
    # Если ошибок не было пишем в лог об успешном подключении
    else:
	xlogger.info("Connection for MySQL Server '%s' (Read) established",mysql_addr)
	# Создаем 'курсор'. (Особая MySQLdb-шная магия)
	mysql_cr   = mysql_db.cursor()
	# Выполняем запрос к базе
	try:
	    mysql_cr.execute(mysql_query)
	# Если возникла ошибка при выполнении запроса пишем в лог об ошибке возвращаем пустой массив
	except MySQLdb.Error as err:
	    xlogger.info("MySQL Read-Query failed: %s",err.args[1]);
	    return {'0':0}
	else:
	    # Получаем все данные из 'курсора'
	    mysql_data = mysql_cr.fetchall()
	    # Пишем в лог об успешном запросе
	    xlogger.info("MySQL Read-Query OK. %s rows found",len(mysql_data))
	    # Возвращаем словарь из полученных данных вида 'ip'=>'id'
	    return dict(list(mysql_data))

def PostDataToMySQL(cr,send_query):
    # Выполняем запрос к базе. Если возникла ошибка ничего не делаем. Если нет, сообщаем, что все хорошо
    try:
	cr.execute(send_query)
    # Если возникла ошибка ничего не делаем
    except:
	pass
    else:
	return True

def ApexSend(apexurl):
    # Пытаемся подключиться к Oracle Apex и пытаемся открыть полученный URL
    try:
	data = urllib2.urlopen(apexurl).read()
	# Проверяем, успешно ли выполнился запрос или возникла ошибка
	if "INSERT_SUCCESS" in data:
	    return True
	elif "class=\"error\"" in data:
	    return False
    except:
	return False
    # Если подключение успешно, но результат неизвестен, ничего не возвращаем. Автоматически вернется None

# ------- Конец блока функций -------

class JabberBot:
    def __init__(self, jid, jps ,jcr, jnn):
        jid = xmpp.JID(jid)
        self.user, self.server, self.password, self.jcr, self.jnn, = jid.getNode(), jid.getDomain(), jps, jcr, jnn

    def connect(self):
        self.conn = xmpp.Client(self.server, debug = [])
        return self.conn.connect()

    def auth(self):
        return self.conn.auth(self.user, self.password)

    def joinroom(self):
        self.conn.sendInitPresence(1)
        self.conn.send(xmpp.Presence(to="%s/%s" % (self.jcr, self.jnn)))

    def proc(self):
        self.conn.Process(1)

    def SendMsg(self, msg):
        self.conn.send(xmpp.protocol.Message(self.jcr,msg,'groupchat'))

    def disconnect(self):
        self.conn.send(xmpp.Presence(typ = 'unavailable'))

    def isAlive(self):
        try:
            self.conn.send(xmpp.Presence(status=None, show=None))
            alive = True
        except IOError:
            alive = False
        return alive

def main():
    # Сообщаем в лог о запуске сервера
    xlogger.info("- = + = - Daemon 'maXys' started - = + = -")

    # Задаем счетчики результатов
    s_cnt    = 0; m_cnt    = 0;
    # Задаем счетчики отправленных записей в MySQL
    s_msql_cnt = 0; m_msql_cnt = 0;
    # Задаем счетчики отправленных записей в Oracle Apex
    s_apex_cnt = 0; m_apex_cnt = 0;
    # Задаем счетчик отправленных записей в Jabber
    s_jbbr_cnt = 0;

    # Начальное значение счетчика длина цепочки данных syslog
    s_chain = 1
    # Начальное значение счетчика длина цепочки данных mactrap
    m_chain = 1

    # Получаем начальное значение таймера, равное текущему времени в unix timestamp
    timer    = int(time.time())
    # Начальное значение таймера накопления данных syslog
    s_ctimer = int(time.time())
    # Начальное значение таймера накопления данных mactrap
    m_ctimer = int(time.time())
    # Получаем список устройств из базы данных
    devices = GetDevicesFromMySQL()

    # Задаем начальное значение переменной, которая содержит статус подключения к MySQL-серверу
    mysql_wready = False

    # Если нужно писать данные в MySQL: (подключаемся первый раз)
    if (write_to_mysql == True):
	# Пробуем подключиться к базе данных MySQL. Используем таймаут в 1 секунду
	try:
	    mysql_db_w = MySQLdb.connect(host=mysql_addr_w, user=mysql_user_w, passwd=mysql_pass_w, db=mysql_base_w, connect_timeout=1)
	# Если возникла ошибка, сообщаем об этом в лог
	except:
	    xlogger.info("Cannot connect to MySQL. The data will not be stored. :(")
	    mysql_wready = False
	# Если ошибок не было пишем в лог об успехе и создаем 'курсор'. (Особая MySQLdb-шная магия)
	else:
	    xlogger.info("Connection for MySQL Server '%s' (Write) established",mysql_addr_w)
	    mysql_cr_w   = mysql_db_w.cursor()
	    mysql_wready = True
	
    # Создаем сокет для syslog
    syslog  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Пробуем открыть сокет для Syslog
    try:
	syslog.bind((interface,sysport))
    # Обрабатываем возможную ошибку сокета (сокет уже занят):
    except socket.error as err:
	# При возникновении ошибки делаем запись в логе и завершаем работу
	xlogger.info("Syslog Error: %s. Exiting...",err.args[1])
	sys.exit(2)
    # При отсутствии ошибки переводим сокет в режим non blocking
    else:
	syslog.setblocking(0)

    # Создаем сокет для mactrap
    mactrap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Пробуем открыть сокет для MacTrap
    try:
	mactrap.bind((interface,macport))
    # Обрабатываем возможную ошибку сокета (сокет уже занят):
    except socket.error as err:
	# При возникновении ошибки делаем запись в логе и завершаем работу
	xlogger.info("MacTrap Error: %s. Exiting...",err.args[1])
	sys.exit(2)
    else: # При отсутствии ошибки переводим сокет в режим non blocking
	mactrap.setblocking(0)

    # Пробуем подключиться к Jabber
    jbot_ok = False
    if useJabber:
	# jid - JID, jps - password, jcr - chat room, jnn - nickname
	jbot = JabberBot(jid,jps,jcr,jnn)
	if jbot.connect():
	    if jbot.auth():
		jbot.joinroom()
		jbot_ok = True
		xlogger.info("Connection to Jabber '%s' established!",jid.split("@")[1])
	    else:
		xlogger.info("Jabber Error: Can't login with ID '%s'!",jid.split("@")[0])
	else:
	    xlogger.info("Jabber Error: Can't connect to '%s'!",jid.split("@")[1])

    # Выполняем бесконечный цикл
    while True:
	# Проверяем, прошло ли нужное количество секунд с момента предыдущего запроса
	if (int(time.time())-timer >= interval):
	    # Если цепочка данных для mactrap не закончена, отправляем данные принудительно:
	    if (m_chain>1):
		# Если включена запись в MySQL:
		if (write_to_mysql == True & mysql_wready == True):
		    if (PostDataToMySQL(mysql_cr_w,m_send_query[:-1]+";") == True):
			# Компенсируем автоматический инкремент счетчиков, отнимая единицу при подсчете
			m_msql_cnt += 1*m_chain-1
		# Если включена запись в Oracle:
		if (write_to_oracle == True):
		    if (ApexSend(m_apexurl[:-22]) == True):
			# Компенсируем автоматический инкремент счетчиков, отнимая единицу при подсчете
			m_apex_cnt += 1*m_chain-1
		# Обновляем таймер и устанавливаем счетчик в 1
		m_ctimer = int(time.time()); m_chain  = 1

	    # Если цепочка данных для syslog не закончена, отправляем данные принудительно:
	    if (s_chain>1):
		# Если включена запись в MySQL:
		if (write_to_mysql == True & mysql_wready == True):
		    if (PostDataToMySQL(mysql_cr_w,s_send_query[:-1]+";") == True):
			# Компенсируем автоматический инкремент счетчиков, отнимая единицу при подсчете
			s_msql_cnt += 1*s_chain-1
		# Если включена запись в Oracle:
		if (write_to_oracle == True):
		    if (ApexSend(s_apexurl[:-22]) == True):
			# Компенсируем автоматический инкремент счетчиков, отнимая единицу при подсчете
			s_apex_cnt += 1*s_chain-1
		# Обновляем таймер и устанавливаем счетчик в 1
		s_ctimer = int(time.time()); s_chain  = 1

	    if useJabber:
		# Проверяем, есть ли подключение к Jabber
		if jbot.isAlive:
		    pass
		else:
		    jbot_ok = False
		    logging.info("WARNING: Not connected to Jabber! Trying to reconnect...")
		    if jbot.connect():
			if jbot.auth():
			    jbot.joinroom()
			    jbot_ok = True
			    xlogger.info("Connection to Jabber '%s' established!",jid.split("@")[1])
			else:
			    xlogger.info("Jabber Error: Can't login with ID '%s'!",jid.split("@")[0])
		    else:
			xlogger.info("Jabber Error: Can't connect to '%s'!",jid.split("@")[1])
		if jbot_ok:
		    jbot.proc()

	    # Пишем в лог общее количество записей и количество записей, успешно переданных в разлиные СУБД
	    xlogger.info("Syslog messages: recieved %s, sended to MySQL %s, sended to Oracle %s",s_cnt,s_msql_cnt,s_apex_cnt)
	    xlogger.info("MAC Notification messages: recieved %s, sended to MySQL %s, sended to Oracle %s",m_cnt,m_msql_cnt,m_apex_cnt)
	    if (useJabber and s_jbbr_cnt>0):
		xlogger.info("Jabber (Syslog) messages sended: %s", s_jbbr_cnt)
	    # Обнуляем счетчики результатов
	    s_cnt    = 0; m_cnt    = 0;
	    s_msql_cnt = 0; m_msql_cnt = 0;
	    s_apex_cnt = 0; m_apex_cnt = 0;
	    s_jbbr_cnt = 0;

	    # Получаем новое значение таймера и делаем новый запрос в базу
	    timer = int(time.time())
	    devices_tmp = GetDevicesFromMySQL()
	    # Если длина запроса составляет не менее 90% от длины предыдущего
	    if (len(devices_tmp) > len(devices)*0.9):
		# Помещаем новый список устройств в основную переменную
		devices = devices_tmp

	    # Если нужно писать данные в MySQL: (переподключаемся на всякий случай)
	    if (write_to_mysql == True):
		# Пробуем закрыть соединение
		try:
		    mysql_db_w.close()
		except:
		    pass
		# Пробуем подключиться к базе данных MySQL. Используем таймаут в 1 секунду
		try:
		    mysql_db_w = MySQLdb.connect(host=mysql_addr_w, user=mysql_user_w, passwd=mysql_pass_w, db=mysql_base_w, connect_timeout=1)
		# Если возникла ошибка, сообщаем об этом в лог
		except:
		    xlogger.info("Cannot connect to MySQL. The data will not be stored. :(")
		    mysql_wready = False
		# Если ошибок не было пишем в лог об успехе и создаем 'курсор'. (Особая MySQLdb-шная магия)
		else:
		    xlogger.info("Connection for MySQL Server '%s' (Write) established",mysql_addr_w)
		    mysql_cr_w   = mysql_db_w.cursor()
		    mysql_wready = True

	# Пробуем получить данные с сокета mactrap
	try: macdata, macaddr = mactrap.recvfrom(512)
	# Если данных нет возникнет ошибка. Ничего не делаем
	except: pass
	# Если ошибки не возникло, значит данные получены. Приступаем к их обработке
	else:
	    mt_act, mt_mac, mt_port = MT_Prepare_Data(macdata)
	    # Если данные обработы корректно:
	    if (mt_act!=False) & (mt_mac!=False) & (mt_port!=False):
		# Увеличиваем значение счетчика для mactrap
		m_cnt += 1
		# Определяем идентификатор устройства
		if macaddr[0] in devices:
		    dev_id = str(devices[macaddr[0]])
		else:
		    dev_id = '0'
		# Определяем IP-адрес устройства
		dev_ip = str(IP2Long(macaddr[0]))
		# Если ID устройства неизвестно, сообщаем об этом в лог
		if (dev_id == 0) & (len(devices)>0):
		    xlogger.info("MacTrap NOTIFY: Recieved MAC Notification-message from %s, but this device not found in database",macaddr[0])
		# Если включена запись в log, формируем строку для лог-файла и пишем данные в лог
		if (write_to_log == True):
		    mlogger.info(" %s%s%s  %s %s  %s",dev_id.rjust(5),dev_ip.rjust(12),mt_act,mt_mac,str(mt_port).rjust(3),int(time.time()))

		# Если цепочка пустая, формируем начало запроса
		if (m_chain==1):
		    m_send_query = "insert into {0}.{1} ({1}.switch_id,{1}.ip,{1}.action,{1}.mac,{1}.port,{1}.datetime) values ".format(mysql_base_w,mysql_mtbl_w)
		    m_apexurl=apex_m_url+apex_m_query.encode("hex")
		# Достраиваем запрос для MySQL
		m_send_query+="('{0}','{1}','{2}','{3}','{4}','{5}'),".format(dev_id,dev_ip,mt_act,mt_mac,mt_port,int(time.time()))
		# Достраиваем ссылку для Oracle Apex
		m_apexurl+="SELECT {0},{1},{2},{3},'{4}',{5} FROM dual UNION ALL ".format(int(time.time()),dev_id,dev_ip,mt_port,mt_mac,mt_act).encode("hex")
		# Если цепочка имеет максимальное значение данных или истек таймаут сбора данных:
		if ((m_chain>=max_chain) or (int(time.time())-m_ctimer>=chain_timeout)):
		    # Если включена запись в MySQL:
		    if (write_to_mysql == True & mysql_wready == True):
			# Если запрос на запись данных в базу MySQL выполнен успешно:
			if (PostDataToMySQL(mysql_cr_w,m_send_query[:-1]+";") == True):
			    # Увеличиваем значение счетчика успешных записей в MySQL для mactrap
			    m_msql_cnt += 1*m_chain
		    # Если включена запись в Oracle:
		    if (write_to_oracle == True):
			# Если запрос на запись данных в базу Oracle выполнен успешно:
			if (ApexSend(m_apexurl[:-22]) == True):
			    # Увеличиваем значение счетчика успешных записей в Oracle для mactrap
			    m_apex_cnt += 1*m_chain

		    # Получаем новое значение таймера mactrap
		    m_ctimer = int(time.time())
		    # Обнуляем значение для счетчика цепочки. Счетчик инкрементируется ниже в любом случае.
		    m_chain  = 0
		# Увеличиваем значение счетчика
		m_chain+=1

	# Пробуем получить данные с сокета syslog
	try: sysdata, sysaddr =  syslog.recvfrom(512)
	# Если данных нет возникнет ошибка. Ничего не делаем
	except: pass
	# Если ошибки не возникло, значит данные получены. Приступаем к их обработке
	else:
	    sl_type, sysdata = SL_Prepare_Data(sysdata)
	    # Если данные обработы корректно:
	    if (sl_type!=False) & (sysdata!=False):
		# Увеличиваем значение счетчика для syslog
		s_cnt += 1
		# Определяем идентификатор устройства
		if sysaddr[0] in devices:
		    dev_id = str(devices[sysaddr[0]])
		else:
		    dev_id = '0'
		# Определяем IP-адрес устройства
		dev_ip = str(IP2Long(sysaddr[0]))
		# Если ID устройства неизвестно, сообщаем об этом в лог
		if (dev_id == 0) & (len(devices)>0):
		    xlogger.info("SysLog  NOTIFY: Recieved SysLog-message from %s, but this device not found in database",sysaddr[0])
		# Если включена запись в log, Формируем строку для лог-файла и пишем данные в лог
		if (write_to_log == True):
		    slogger.info(" %s%s  %s  %s  %s",dev_id.rjust(5),dev_ip.rjust(12),int(time.time()),sl_type,sysdata)

		# Если цепочка пустая, формируем запрос для записи в базу данных и помещаем в него данные:
		if (s_chain==1):
		    s_send_query = ("insert into {0}.{1} ({1}.switch_id,{1}.ip,{1}.type,{1}.data,{1}.datetime) values ").format(mysql_base_w,mysql_stbl_w)
		    s_apexurl=apex_s_url+apex_s_query.encode("hex")
		# Достраиваем запрос для MySQL
		s_send_query+="('{0}','{1}','{2}',SUBSTR('{3}',1,160),'{4}'),".format(dev_id,dev_ip,sl_type,sysdata,int(time.time()))
		# Достраиваем ссылку для Oracle Apex
		s_apexurl+="SELECT {0},{1},{2},{3},'{4}' FROM dual UNION ALL ".format(int(time.time()),dev_id,dev_ip,sl_type,sysdata).encode("hex")

		# Если цепочка имеет максимальное значение данных или истек таймаут сбора данных:
		if ((s_chain>=max_chain) or (int(time.time())-s_ctimer>=chain_timeout)):
		    # Если включена запись в MySQL:
		    if (write_to_mysql == True & mysql_wready == True):
			# Если запрос на запись данных в базу MySQL выполнен успешно:
			if (PostDataToMySQL(mysql_cr_w,s_send_query[:-1]+";") == True):
			    # Увеличиваем значение счетчика успешных записей в MySQL для syslog
			    s_msql_cnt += 1*s_chain
		    # Если включена запись в Oracle:
		    if (write_to_oracle == True):
			# Если запрос на запись данных в базу Oracle выполнен успешно:
			if (ApexSend(s_apexurl[:-22]) == True):
			    # Увеличиваем значение счетчика успешных записей в Oracle для syslog
			    s_apex_cnt += 1*s_chain

		    # Получаем новое значение таймера syslog
		    s_ctimer = int(time.time())
		    # Обнуляем значение для счетчика цепочки. Счетчик инкрементируется ниже в любом случае.
		    s_chain  = 0
		# Увеличиваем значение счетчика
		s_chain+=1

		send_to_jabber = False
		if (useJabber and jbot_ok):
		    for stj_inc in systojab_inc:
			if stj_inc in sysdata:
			    send_to_jabber = True
		    for stj_exc in systojab_exc:
			if stj_exc in sysdata:
			    send_to_jabber = False
		    if send_to_jabber:
			try:
			    jbot.SendMsg(sysdata)
			except:
			    xlogger.info("Jabber Error: Can't send message!")
			else:
			    s_jbbr_cnt+=1

	time.sleep(0.001)

# ------- Служебный блок: создание и управление демоном -------

class MyDaemon(Daemon):
    def run(self):
	main()

if __name__ == "__main__":
    daemon = MyDaemon('/var/run/maXys.pid','/dev/null',logmaXys,logmaXys)
    if len(sys.argv) == 2:
	if   'start'     == sys.argv[1]:
	    daemon.start()
	elif 'faststart' == sys.argv[1]:
	    daemon.start()
	elif 'stop'      == sys.argv[1]:
	    daemon.stop()
	elif 'restart'   == sys.argv[1]:
	    daemon.restart()
	else:
	    print "maXys: "+sys.argv[1]+" - unknown command"
	    sys.exit(2)
	sys.exit(0)
    else:
	print "usage: %s start|stop|restart" % sys.argv[0]
	sys.exit(2)

# ------- Конец служебного блока -------
