#coding=utf-8
__author__ = 'zxlee'
import json
import time
import HttpReq
import sys
import os
import platform
from dateutil.parser import parse
import Encrypt

#是否是Windows
os_is_windows = platform.system() == 'Windows'
#用户登录后授权的token
token = ''
#用户登录后授权的secret
secret = ''
#用户id
uid = ''
#程序入口
def main():
	while (True):
		user_login = get_user_login()
		account = user_login['account']
		pwd = user_login['pwd']
		#provinceCode根据学校来改
		res = HttpReq.send_req('/api/f/v6/login',{'username':account,'password':Encrypt.get_enc_pwd(pwd),'provinceCode':35,'randomCode':34},'POST','')
		if 'message' in res:
			msg = res['message']
			if msg == 'OK':
				global uid,token,secret
				name = res['data']['info']['xm']
				#uid = res['data']['info']['uid']
				uid = account
				auth = res['data']['token']
				auths = auth.split('.')
				token = '%s.%s.%s'%(auths[0],auths[1],auths[2])
				secret = auths[3]
				print(u'登录成功,欢迎您：' + name + u'同学！')
				print('token:' + token)
				print('secret:' + secret)
				break
			else:
				print(u'登录失败！' + msg)
		else:
			print(u'登录失败！' + str(res))
			

#根据系统获取raw_input中文编码结果
def gbk_encode(str):
	if os_is_windows:
		return str.decode('utf-8').encode('gbk')
	else:
		return str


#获取用户输入搜索条件
def get_user_login():
	account = raw_input(gbk_encode('请输入账号: ')).decode(sys.stdin.encoding)
	pwd = raw_input(gbk_encode('请输入密码: ')).decode(sys.stdin.encoding)
	return {'account':account,'pwd':pwd}



main()

