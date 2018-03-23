install:
	sudo cp ./gonetmon /usr/local/bin/
	sudo cp ./gonetmon.conf /etc/init/ 
	service gonetmon start

stop:
	service gonetmon stop

start:
	service gonetmon start

restart:
	service gonetmon restart
