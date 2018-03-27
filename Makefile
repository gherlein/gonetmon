install:
	sudo cp ./gonetmon /usr/local/bin/
	sudo cp ./gonetmon.toml /etc/
	sudo cp ./gonetmon.service /etc/systemd/system
	sudo systemctl daemon-reload
	sudo systemctl enable gonetmon
	sudo systemctl start gonetmon


stop:
	sudo service gonetmon stop

start:
	sudo service gonetmon start

restart:
	sudo service gonetmon restart
