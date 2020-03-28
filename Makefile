NAME   := gonetmon


all: 
	go build

dependencies:
	go get ./...
	sudo apt-get install libpcap-dev

install: ${NAME}
	sudo systemctl stop ${NAME}
	sudo cp ${NAME} /usr/local/bin/
	sudo cp ${NAME}.toml /etc/
	sudo cp ${NAME}.service /etc/systemd/system
	sudo systemctl daemon-reload
	sudo systemctl enable ${NAME}
	sudo systemctl start ${NAME}

stop:
	sudo service ${NAME} stop

start:
	sudo service ${NAME} start

restart:
	sudo service ${NAME} restart

clean:
	-rm -f ${NAME}
	-rm -f *~
