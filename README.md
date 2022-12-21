[![pylint](https://github.com/zerwes/opnsense-fail2ban/actions/workflows/pylint.yml/badge.svg)](https://github.com/zerwes/opnsense-fail2ban/actions/workflows/pylint.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

# opnsense-fail2ban
fail2ban action script for opnsense

## features

 * ban action i.e. add a new IP to the alias
 * unban action i.e. remove a IP from the alias
 * flush action i.e. clear all IPs from the alias
 * list action i.e. display the IPs from the alias
 * optional: check if the IP is listed or removed from the alias
 * optional: kill all states for the IP in questio after adding it to the alias
 * use a predefined alias by default or define it via a argument

## usage

```
usage: opnsense-fail2ban.py [-h] [-l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}] [-g GROUP]
                            [-a {ban,unban,flush,list}] [-i IP] [-c] [-k]

manipulate a opnsense alias by adding/removing IPs

optional arguments:
  -h, --help            show this help message and exit
  -l {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}, --loglevel {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        set loglevel
  -g GROUP, --group GROUP
                        group/alias for actions (default: {{ opnsense_default_alias }})
  -a {ban,unban,flush,list}, --action {ban,unban,flush,list}
                        action to perform
  -i IP, --ip IP        IP to ban/unban
  -c, --check           re-fetch and check alias after ban/unban
  -k, --kill            kill states after ban action for a IP
```

## requirements

All requirements are defined in [requirements.txt](requirements.txt).

You can install them using:
```
pip install -r requirements.txt
```

On debian and derivates you can use:
```
apt install python3-simplejson python3-requests
```
if you prefer to use the package manager instead of pip.

## setup

The script uses jinja2 variables, so you have several options:

### ansible

Install the script using ansible and define the variables in your ansible var files.

### jinja2-cli

Define your vars in a yaml file `jinja2.yml` (see [sample-jinja2.yml](sample-jinja2.yml)) and run:
```
make 
```
This will install `jinja2-cli` and generate `script/opnsense-fail2ban.py` with the jinja2 vars replaced according to your settings.

### manual

Edit `opnsense-fail2ban.py` and replace the jinja2 vars:

 * `{{ opnsense_api_host }}`
 * `{{ opnsense_api_key }}`
 * `{{ opnsense_api_secret }}`
 * `{{ opnsense_default_alias }}`

## caveats

In case you use a self-signed certificate on the opnsense firewall, you must import the opnsense (ca) certificate in order to trust it.
