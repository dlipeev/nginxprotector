import re
import sys
import os
import time


bad_ips = []
ALREADY_BLOCKED_IPS_LIST = './already_blocked_ips'
already_blocked_ips = []

ip_freq = {}

WHITELIST = [
    '95.31.224.79',
    '127.0.0.1',
    '92.53.119.200'
]
ALLOWED_METHODS = [
    'GET', 'POST'
]


DDOS_THRESHOLD = 100


#regex = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) - "(.*?)" "(.*?)"'
#regex = re.compile('([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) - "(.*?)" "(.*?)"')
regex_main = re.compile('([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"')



def count_ip(ip):
    global WHITELIST
    global ip_freq
    if ip in WHITELIST:
        return
    if ip in ip_freq:
        ip_freq[ip] += 1
    else:
        ip_freq[ip] = 1

def add_ip(ip):
    global WHITELIST
    global bad_ips
    if ip in WHITELIST:
        return
    if ip in already_blocked_ips:
        return
    if ip not in bad_ips:
        bad_ips.append(ip)

def blame_ips(ips):
    if not ips:
        return
    with open(ALREADY_BLOCKED_IPS_LIST, 'a') as the_file:
        for bad_ip in ips:
            the_file.write(f'{bad_ip}\n')
            os.system(f'iptables -I INPUT 4 -p tcp -j DROP -s {bad_ip}')


if os.path.exists(ALREADY_BLOCKED_IPS_LIST):
    with open(ALREADY_BLOCKED_IPS_LIST, 'r') as f:
        tmp = f.readlines()
    for rec in tmp:
        already_blocked_ips.append(rec.strip())

print(already_blocked_ips)

try:
    for line in sys.stdin:
        # print(line)
        #line = f.readline()
        try:
            ip, date, request, response_code, response_size, referer, useragent = regex_main.match(line).groups()
        except AttributeError:
            break
        # print(ip, date, request, response_code, response_size, referer, useragent)
        parsed_request = request.split(' ')
        try:
            if parsed_request[1] == '/':
                count_ip(ip)
            if parsed_request[0] not in ALLOWED_METHODS:
                add_ip(ip)
        except IndexError:
            #   эта ситуация обозначает что в параметрах запроса полное говнище со спецсимволами, таких сразу в печку
            add_ip(ip)
            continue
except KeyboardInterrupt:
    pass
finally:
    print('останавливаемся...')
    ip_freq_sorted = sorted(ip_freq.items(), key=lambda x: x[1], reverse = True)
    for rec in ip_freq_sorted:
        if rec[1] > DDOS_THRESHOLD:
            add_ip(rec[0])
    for ip in bad_ips:
        print(ip)
    blame_ips(bad_ips)


