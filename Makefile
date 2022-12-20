# requires:
export SHELL = /bin/bash

script: opnsense-fail2ban.py jinja2.yml
	jinja2 --strict --format=yaml -o opnsensefail2ban.py opnsense-fail2ban.py jinja2.yml
	chmod 700 opnsensefail2ban.py

requirements:
	pip install jinja2-cli
