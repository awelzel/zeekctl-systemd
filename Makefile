DOCKER ?= docker
TAG ?= zeek/zeek-dev-systemd
NAME ?= zeek-cluster
TIMEOUT ?= 5

.PHONY: container up down enter
container:
	$(DOCKER) build -f docker/Dockerfile . -t $(TAG)

up:
	$(DOCKER) run -d --privileged --name $(NAME) $(TAG)

down:
	$(DOCKER) stop -t $(TIMEOUT) $(NAME)
	$(DOCKER) rm $(NAME)

enter:
	$(DOCKER) exec -it $(NAME) /bin/bash

status:
	$(DOCKER) exec $(NAME) systemctl status
