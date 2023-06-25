import re
import sys
import time
import json
import psutil
import socket
import threading
import subprocess
import tkinter as tk
from scapy.all import *
import ipaddress as ipa
import tkinter.ttk as ttk
from urllib.request import urlopen
from subprocess import check_output
from urllib.request import urlretrieve

rip = ''
r6_ports = []
saved_ips = []
gameMode = 'R6S'
proto_whitelist = [6, 17]
ip_whitelist = [
	'43.201.104.85',
	'52.202.184.16',
	'52.21.124.134',
	'54.230.167.89',
	'203.132.26.78',
	'203.132.26.137'
]
ip_blacklist = []

def exit_program():
	sys.exit()

def get_pid(name):
	for proc in psutil.process_iter():
		if name in proc.name():
			return proc.pid
			break

def stop_sniffing(x):
	global switch
	return switch

def sniffing():
	print('Started sniffing')
	sniff(filter='ip', prn=packetHandler, count=0, stop_filter=stop_sniffing)
	print('Sniffing finished')

def applyGameMode():
	global gameMode
	gameMode = gameModeSelectBox.get()
	get_ports()

def start_button():
	global switch
	global thread
	if thread is None or not thread.is_alive():
		switch = False
		thread = threading.Thread(target=sniffing)
		thread.start()
	else:
		print('DEBUG: already running')

def stop_button():
	global switch
	print('DEBUG: stoping')
	switch = True

def allow_whitelist():
	global ip_whitelist
	subprocess.run(r'netsh advfirewall firewall delete rule name="r6kr"')
	for ip in ip_whitelist:
		subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=in action=allow remoteip={ip}')
		subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=out action=allow remoteip={ip}')

def get_ports():
	global r6_ports, gameMode
	print('Looking for the port connected to R6S... (Can take a lot of time)')
	if gameMode == 'R6S':
		procName = 'RainbowSix.exe'
	elif gameMode == 'R6S_VULKAN':
		procName = 'RainbowSix_Vulkan.exe'
	for con in psutil.net_connections(kind='all'):
		if con.pid == get_pid(procName):
			r6_ports.append(con.laddr[1])
	print(f'Port lookup done: {r6_ports}')

def packetHandler(packet):
	global rip, r6_ports, ip_blacklist, proto_whitelist
	src = packet[0][1].src
	dst = packet[0][1].dst
	proto = packet[0][1].proto
	if proto in proto_whitelist:
		if packet[0][1].sport in r6_ports or packet[0][1].dport in r6_ports:
			lip = socket.gethostbyname(socket.gethostname())
			if src == lip:
				rip = dst
			elif dst == lip:
				rip = src
			res = json.loads(check_output(f'ipinfo {rip} -j'))
			if 'bogon' not in res.keys():
				if res["country"] == 'KR':
					print(f'{res["ip"]} {res["org"]}')
				else:
					if res["ip"] not in ip_whitelist:
						if res['ip'] not in ip_blacklist:
							print(f'Disconnect: {res["ip"]}')
							subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=in action=block remoteip={res["ip"]}')
							subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=out action=block remoteip={res["ip"]}')
							ip_blacklist.append(res['ip'])

thread = None
switch = False
infoText = """- 사용 방법
1. 레식을 켜주세요.
2. 맨 위 선택창에서 어떤 버전의 레식을 실행했는지 선택해주세요. (일반, VULKAN)
3. 선택 완료 후 바로 밑에 있는 저장 버튼을 눌러주세요.
4. 한국 서버 고정을 2개의 버튼으로 켜고 끄실 수 있습니다.
5. 프로그램 종료 버튼을 눌러 프로그램을 종료하실 수 있습니다.
- 주의사항
1. 아직 이 프로그램은 미완성 베타 테스트이며 모든 책임은 프로그램 실행자 본인에게 있습니다.
2. 이 프로그램에 대하여 무단 복제 및 배포를 금지합니다. (제작자: kyky775@gmail.com)
3. 이 프로그램은 방화벽을 사용하여 작동합니다. 반드시 관리자 권한으로 실행해주세요.
4. 가끔씩 레식 인게임에서 오류 창이 뜰 수 있으나 지극히 정상적인 현상입니다. 추후 고치겠습니다.
- 프로그램 정보
만든 이 (연락처): kyky775@gmail.com
버전: 23.6.26.0"""

allow_whitelist()

window = tk.Tk()
#window.iconbitmap("icon.ico")
window.title("R6S KR SERVER FIXER v1")
window.config(bg='#FFFFFF')
window.resizable(False, False)
window.geometry("1280x720+0+0")

gameModeSelectBox = ttk.Combobox(window, values=['R6S', 'R6S_VULKAN'], state="readonly")
gameModeSelectBox.current(0)
gameModeSelectBox.pack()

applyGameModeBtn = tk.Button(window, text='저장', command=applyGameMode)
applyGameModeBtn.pack()

startMonitorBtn = tk.Button(window, text='한국 서버 고정 켜기', command=start_button)
startMonitorBtn.pack()

startMonitorBtn = tk.Button(window, text='한국 서버 고정 끄기', command=stop_button)
startMonitorBtn.pack()

exitMonitorBtn = tk.Button(window, text='프로그램 종료', command=exit_program)
exitMonitorBtn.pack()

infoTextLabel = tk.Label(window, text=infoText)
infoTextLabel.pack()

window.mainloop()
