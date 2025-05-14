PHONY: build

build:
	go build -o collector ./main.go


PHONY: init
init:
	multipass launch 22.04 \
	--name collector-vm \
	--memory 2G \
	--disk 5G \
	--cloud-init multipass-cloud-init.yaml

PHONY: reset
reset:
	multipass delete collector-vm
	multipass purge
	make init

PHONY: tail
tail:
	multipass exec collector-vm -- sudo tail -n 1 /var/log/collector.log
