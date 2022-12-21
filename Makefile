# requires:
export SHELL = /bin/bash

all: requirements script

script: script/opnsense-fail2ban.py

script/opnsense-fail2ban.py: opnsense-fail2ban.py jinja2.yml
	test -d $(dir $@) || mkdir $(dir $@)
	jinja2 --strict --format=yaml -o $@ $?
	chmod 700 $@
	@echo "wrote '$@'"

requirements:
	pip install jinja2-cli
