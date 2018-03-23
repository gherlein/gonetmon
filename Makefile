install:
	sudo cp ./gonetmon /usr/local/bin/
	sudo cp ./gonetmon.conf /etc/init/ 
	service gonetmon start

stop:
	sudo service gonetmon stop

start:
	sudo service gonetmon start

restart:
	sudo service gonetmon restart
