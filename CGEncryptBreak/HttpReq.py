#coding=utf-8
__author__ = 'zxlee'
import json
import requests
from requests.cookies import RequestsCookieJar
import urlparse
import base64
import re
import Encrypt
import time
import datetime
import urllib
import operator
main_url = 'http://210.34.81.129/cgapp-server/'
def json_dic(json_str):
	try:
		json_object = json.loads(json_str)
	except ValueError, e:
		json_object = {}
	return json_object

def send_req(interface,data,post_type,token):
	#sorted_data = {}
	data = dict(sorted(data.items(),key=lambda d:d[1],reverse=True))
	data_str = urllib.urlencode(data)
	url = main_url + interface
	up = urlparse.urlparse(url)
	timestamp = str(int(round(time.time() * 1000)))
	org_headers = {
		"Accept": "*/*",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-Hans-CN;q=1",
		"Connection": "close",
		"Content-Length":str(len(data_str)),
		"Content-Type": "application/x-www-form-urlencoded",
		"Host": up.netloc,
		"User-Agent": "ChingoItemCGTY(Linux; iOS 12.1;iPhone HUUID/13FDADFB-0EF7-4BDE-9631-65F08BA6BC31)",
		"app-key": "azk3t4jrcfm5772t",
		"sign":Encrypt.get_sign(interface,data,timestamp),
		"timestamp":timestamp
	}
	if len(token):
		org_headers.update({'cgAuthorization':token})
	if post_type.upper() == 'POST':
		res = requests.post(url,data=data_str,headers=org_headers)
	elif post_type.upper() == 'PUT':
		res = requests.put(url,data=data_str,headers=org_headers)
	elif post_type.upper() == 'GET':
		res = requests.get(url,data=data_str,headers=org_headers)
	else:
		print('TypeErr')
	#if res.status_code != requests.codes.ok:	
	return json_dic(res.text)







