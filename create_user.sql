CREATE USER 'macsys'@'%' IDENTIFIED BY 'macsyspassword';
GRANT USAGE ON `maxys`.* TO 'macsys'@'%';
GRANT ALL PRIVILEGES ON `maxys`.* TO 'macsys'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;