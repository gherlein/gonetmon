./gonetmon: build

build: dependencies ./gonetmon
	go build

dependencies:
	go get github.com/coreos/go-systemd/daemon
	go get github.com/google/gopacket
	go get github.com/google/gopacket/layers
	go get github.com/google/gopacket/pcap
	go get github.com/onsi/gocleanup
	go get github.com/prometheus/client_golang/prometheus
	go get github.com/prometheus/client_golang/prometheus/promhttp
	go get github.com/spf13/viper

install: ./gonetmon
	sudo systemctl stop gonetmon
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

clean:
	-rm -f ./gonetmon
	-rm -f *~
