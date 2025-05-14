.PHONY: build

build:
	go build -o collector ./main.go


.PHONY: init
init:
	multipass launch 22.04 \
	--name collector-vm \
	--memory 2G \
	--disk 5G \
	--cloud-init multipass-cloud-init.yaml

.PHONY: kill
kill:
	multipass delete collector-vm
	multipass purge

.PHONY: reset
reset:
	make kill
	make init

.PHONY: tail
tail:
	multipass exec collector-vm -- sudo tail -n 1 /var/log/collector.log

.PHONY: passwd
passwd:
	multipass exec collector-vm -- bash -c 'cat /etc/passwd > /dev/null'

.PHONY: google
google:
	multipass exec collector-vm -- bash -c 'nc -zv 8.8.8.8 53 || true'
