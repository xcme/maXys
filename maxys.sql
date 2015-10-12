-- Дамп структуры базы данных maxys
CREATE DATABASE IF NOT EXISTS `maxys` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `maxys`;


-- Дамп структуры для таблица maxys.mactrap
CREATE TABLE IF NOT EXISTS `mactrap` (
  `id` int(4) unsigned NOT NULL AUTO_INCREMENT,
  `switch_id` smallint(2) unsigned NOT NULL DEFAULT '0',
  `ip` int(4) unsigned NOT NULL,
  `action` tinyint(1) unsigned NOT NULL,
  `mac` char(12) NOT NULL,
  `port` tinyint(1) unsigned NOT NULL,
  `datetime` int(4) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `switch_id` (`switch_id`),
  KEY `switch_id_port` (`switch_id`,`port`),
  KEY `ip` (`ip`),
  KEY `datetime` (`datetime`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


-- Дамп структуры для таблица maxys.syslog
CREATE TABLE IF NOT EXISTS `syslog` (
  `id` int(4) unsigned NOT NULL AUTO_INCREMENT,
  `switch_id` smallint(2) unsigned NOT NULL DEFAULT '0',
  `ip` int(4) unsigned NOT NULL,
  `type` tinyint(1) unsigned NOT NULL,
  `data` char(160) NOT NULL,
  `datetime` int(4) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `switch_id` (`switch_id`),
  KEY `datetime` (`datetime`),
  KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

