#! /usr/bin/env python3
# vim: set fileencoding=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 smartindent

# manipulate the opnsense alias by adding/removing IPs
#
# ban:
#   opnsense-fail2ban.py -l DEBUG -a ban -i 11.22.33.44 -c
#
# unban:
#   opnsense-fail2ban.py -l DEBUG -a unban -i 11.22.33.44 -c


# requires ca / host cert
# in order to avoid Error SSL routines certificate verify failed

# helpful hints found in the src code from opnsense-core
# https://docs.opnsense.org/development/api/core/firewall.html
# src/opnsense/mvc/app/views/OPNsense/Firewall/alias_util.volt
# src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasUtilController.php
# src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasController.php
# https://docs.opnsense.org/development/api/core/diagnostics.html
# src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/FirewallController.php

# pylint: disable=invalid-name,missing-module-docstring,redefined-outer-name

import sys
import pprint
import logging
import argparse
import json
import requests

# define endpoint and credentials
api_key = '{{ opnsense_api_key }}'
api_secret = '{{ opnsense_api_secret }}'

# /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
api_url = 'https://{{ opnsense_api_host }}/api'
#url = 'https://{{ opnsense_api_host }}/api/firewall/alias'
#url_diag = 'https://{{ opnsense_api_host }}/api/diagnostics/firewall'

# default alias to use
default_alias = '{{ opnsense_default_alias }}'

class LoggingAction(argparse.Action): # pylint: disable=missing-class-docstring
    def __call__(self, parser, namespace, values, option_string=None):
        # print '%r %r %r' % (namespace, values, option_string)
        logger = logging.getLogger()
        logger.setLevel(values)
        setattr(namespace, self.dest, values)

def get_request(uriparams):
    """peform a get request on the alias API"""
    r = requests.get('%s/%s/%s' % (url, uriparams,), auth=(api_key, api_secret))
    if r.status_code == 200:
        return json.loads(r.text)
    sys.exit('ERROR @ request: %s :: %s' % (r.status_code, r.text,))

def get_states(ip):
    """query states for a defined IP"""
    purl = '%s/%s/queryStates' % (api_url, 'diagnostics/firewall')
    headers = {'Content-Type': 'application/json'}
    r = requests.post(
        purl,
        headers=headers,
        json={'searchPhrase': '%s' % ip},
        auth=(api_key, api_secret)
        )
    if r.status_code == 200:
        return json.loads(r.text)
    sys.exit('ERROR @ get_states: %s :: %s' % (r.status_code, r.text,))

def kill_states(ip):
    """kill all states for a defined IP"""
    purl = '%s/%s/killStates' % (api_url, 'diagnostics/firewall')
    headers = {'Content-Type': 'application/json'}
    r = requests.post(
        purl,
        headers=headers,
        json={'filter': '%s' % ip},
        auth=(api_key, api_secret)
        )
    if r.status_code == 200:
        return json.loads(r.text)
    sys.exit('ERROR @ kill_states: %s :: %s' % (r.status_code, r.text,))


logger = logging.getLogger()
logging.basicConfig(
    level=logging.WARN,
    format='%(levelname)s\t[%(name)s] %(funcName)s: %(message)s'
    )

parser = argparse.ArgumentParser(description='manipulate the opnsense alias by adding/removing IPs')
# pylint: disable=protected-access
parser.add_argument(
    '-l', '--loglevel',
    help='set loglevel',
    type=str,
    choices=[k for k in logging._nameToLevel if isinstance(k, str)],
    action=LoggingAction
    )
parser.add_argument(
    '-g', '--group', type=str,
    default=default_alias,
    help='main group/alias for actions'
    )
parser.add_argument(
    '-a', '--action', type=str,
    choices=['ban', 'unban', 'flush', 'list'],
    default='list',
    help='action to perform'
    )
parser.add_argument(
    '-i', '--ip', type=str,
    help='IP to ban/unban'
    )
parser.add_argument(
    '-c', '--check',
    action='store_true', default=False,
    help='re-fetch cont after ban/unban'
    )
parser.add_argument(
    '-k', '--kill',
    action='store_true', default=False,
    help='kill states after ban action for a IP'
    )

args = parser.parse_args()

if args.loglevel is None:
    logging.disable(logging.CRITICAL)

# getAliasUUID
r = get_request('getAliasUUID/%s' % args.group)
if logger.isEnabledFor(logging.DEBUG):
    pprint.PrettyPrinter(indent=4).pprint(r)
gUUID = r['uuid']

# get current members
# FIXME: easier way using alias_util # pylint: disable=fixme
#r = requests.get('%s_util/list/%s' % (url, args.group), auth=(api_key, api_secret))
#pprint.PrettyPrinter(indent=4).pprint(r)
#pprint.PrettyPrinter(indent=4).pprint(json.loads(r.text))
r = get_request('getItem/%s' % gUUID)
if logger.isEnabledFor(logging.DEBUG):
    pprint.PrettyPrinter(indent=4).pprint(r)
aliascontlist = r['alias']['content']
aliascont = []
for name, settings in aliascontlist.items():
    if settings['selected'] == 1 and len(name) > 0:
        aliascont.append(name)
if logger.isEnabledFor(logging.DEBUG):
    pprint.PrettyPrinter(indent=4).pprint(aliascont)

if args.action == 'list':
    if aliascont:
        print('alias/group "%s" has the members: %s' % (args.group, ';'.join(aliascont)))
    else:
        print('alias/group "%s" has no members' % args.group)
    sys.exit()

if args.action == 'ban':
    if not args.ip:
        sys.exit('ERROR: missing IP')
    if args.ip in aliascont:
        logger.warning(
            'no need to ban IP %s as it already in the list %s', args.ip, ';'.join(aliascont)
            )
        sys.exit()
    purl = '%s_util/add/%s' % (url, args.group)
    headers = {'Content-Type': 'application/json'}
    r = requests.post(
        purl,
        headers=headers,
        json={'address': '%s' % args.ip},
        auth=(api_key, api_secret)
        )
    if r.status_code == 200:
        logger.info('OK w/ code %s', r.status_code)
    else:
        if logger.isEnabledFor(logging.DEBUG):
            pprint.PrettyPrinter(indent=4).pprint(r)
        sys.exit('ERROR @ post: %s :: %s' % (r.status_code, r.text,))

    if args.check:
        r = get_request('getItem/%s' % gUUID)
        #if logger.isEnabledFor(logging.DEBUG):
        #    pprint.PrettyPrinter(indent=4).pprint(r)
        aliascontlist = r['alias']['content']
        aliascont = []
        for name, settings in aliascontlist.items():
            if settings['selected'] == 1 and len(name) > 0:
                aliascont.append(name)
        logger.debug('current cont: "%s"', '; '.join(aliascont))
        if args.ip in aliascont:
            logger.info('OK: new IP found in cont')
        else:
            sys.exit('ERROR: missing new IP in cont')

    if args.kill:
        rkill = kill_states(args.ip)
        if logger.isEnabledFor(logging.DEBUG):
            pprint.PrettyPrinter(indent=4).pprint(rkill)

if args.action == 'unban':
    if not args.ip:
        sys.exit('ERROR: missing IP')
    if args.ip not in aliascont:
        logger.warning(
            'no need to unban IP %s as it is not in the list %s', args.ip, ';'.join(aliascont)
            )
        sys.exit()
    purl = '%s_util/delete/%s' % (url, args.group)
    headers = {'Content-Type': 'application/json'}
    r = requests.post(
        purl,
        headers=headers,
        json={'address': '%s' % args.ip},
        auth=(api_key, api_secret)
        )
    if r.status_code == 200:
        logger.info('OK w/ code %s', r.status_code)
    else:
        if logger.isEnabledFor(logging.DEBUG):
            pprint.PrettyPrinter(indent=4).pprint(r)
        sys.exit('ERROR @ post: %s :: %s' % (r.status_code, r.text,))

    if args.check:
        r = get_request('getItem/%s' % gUUID)
        #if logger.isEnabledFor(logging.DEBUG):
        #    pprint.PrettyPrinter(indent=4).pprint(r)
        aliascontlist = r['alias']['content']
        aliascont = []
        for name, settings in aliascontlist.items():
            if settings['selected'] == 1 and len(name) > 0:
                aliascont.append(name)
        logger.debug('current cont: "%s"', '; '.join(aliascont))
        if args.ip in aliascont:
            sys.exit('ERROR: IP still found in cont')
        else:
            logger.info('OK: missing new IP in cont')

if args.action == 'flush':
    if not aliascont:
        logger.warning('no need to flush %s as it is empty', args.group)
        sys.exit()
    # upstream issue https://github.com/opnsense/core/issues/4196
    # flush seems not to be persistent
    logger.info('delete: %s', ','.join(aliascont))
    purl = '%s_util/delete/%s' % (url, args.group)
    headers = {'Content-Type': 'application/json'}
    for ip in aliascont:
        logger.info('delete %s ...', ip)
        r = requests.post(
            purl,
            headers=headers,
            json={'address': '%s' % ip},
            auth=(api_key, api_secret)
            )
        if logger.isEnabledFor(logging.DEBUG):
            pprint.PrettyPrinter(indent=4).pprint(r)
        if r.status_code == 200:
            logger.info('OK w/ code %s', r.status_code)
        else:
            sys.exit('ERROR @ post: %s :: %s' % (r.status_code, r.text,))

    #r = requests.get('%s_util/list/%s' % (url, args.group), auth=(api_key, api_secret))
    #pprint.PrettyPrinter(indent=4).pprint(r)
    #pprint.PrettyPrinter(indent=4).pprint(json.loads(r.text))
    if args.check:
        r = get_request('getItem/%s' % gUUID)
        aliascontlist = r['alias']['content']
        aliascont = []
        for name, settings in aliascontlist.items():
            if settings['selected'] == 1 and len(name) > 0:
                aliascont.append(name)
        logger.debug('current cont: "%s"', '; '.join(aliascont))
        if aliascont:
            sys.exit('ERROR: list is not flushed')
        else:
            logger.info('OK: list is empty')
    r = requests.get('%s_util/list/%s' % (url, args.group))
    pprint.PrettyPrinter(indent=4).pprint(r)
