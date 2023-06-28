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
r6_ips = []
azr_ips = []
r6_ports = []
saved_ips = []
gameMode = 'R6S'
ip_whitelist = []
ip_blacklist = []
hostname_whitelist = []
proto_whitelist = [6, 17]

def exit_program():
	sys.exit()

def refresh_db():
	apply_list()
	apply_azr_ips()
	apply_whitelist()
	allow_whitelist()

def get_pid(name):
	for proc in psutil.process_iter():
		if name in proc.name():
			return proc.pid
			break

def apply_azr_ips():
	global azr_ips
	azr_ips = json.loads(urlopen('https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230626.json').read())['values']

def stop_sniffing(x):
	global switch
	return switch

def sniffing():
	print('Started fixing')
	sniff(filter='ip', prn=packetHandler, count=0, stop_filter=stop_sniffing)
	print('Fixing stopped')

def applyGameMode():
	global gameMode
	gameMode = gameModeSelectBox.get()
	get_ports()

def apply_list():
	global r6_ips
	r6_ips = json.loads(urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json').read())['prefixes']

def apply_whitelist():
	global ip_whitelist
	whitelists = json.loads(urlopen('http://r6krfixer.kro.kr/getIp').read())
	ip_whitelist = whitelists['ip_whitelist']
	hostname_whitelist = whitelists['hostname_whitelist']

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

def delete_firewalls():
	subprocess.run(r'netsh advfirewall firewall delete rule name="r6kr"')

def allow_whitelist():
	global ip_whitelist
	subprocess.run(r'netsh advfirewall firewall delete rule name="r6kr"')
	for ip in ip_whitelist:
		subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=in action=allow remoteip={ip}')
		subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=out action=allow remoteip={ip}')

def get_azr_loc(ip):
	global azr_ips
	for azr_data in azr_ips:
		for azr_ip_range in azr_data['properties']['addressPrefixes']:
			if ipa.ip_address(ip) in ipa.ip_network(azr_ip_range):
				return azr_data['properties']['region']
				break

def get_ports():
	global r6_ports, gameMode
	print('Looking for the port connected to R6S...')
	if gameMode == 'R6S':
		procName = 'RainbowSix.exe'
	elif gameMode == 'R6S_VULKAN':
		procName = 'RainbowSix_Vulkan.exe'
	for con in psutil.net_connections(kind='all'):
		if con.pid == get_pid(procName):
			r6_ports.append(con.laddr[1])
	print(f'Port lookup done: {r6_ports}')

def packetHandler(packet):
	global rip, r6_ports, ip_whitelist, ip_blacklist, proto_whitelist
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
				if 'hostname' in res and res['hostname'] in hostname_whitelist:
					print('Whitelisted hostname. skipping...')
				else:
					idx = next((i for (i, d) in enumerate(r6_ips) if ipa.ip_address(rip) in ipa.ip_network(d['ip_prefix'])), None)
					if idx is not None:
						#AWS
						if r6_ips[idx]['region'] == 'ap-northeast-2':
							print(f'{rip} is AWS KR Server')
						else:
							if rip not in ip_whitelist:
								if rip not in ip_blacklist:
									subprocess.run(f'cports /close * * {rip} *')
									subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=in action=block remoteip={res["ip"]}')
									subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=out action=block remoteip={res["ip"]}')
									print(f'Blocked and dropped connection to: {rip}')
									ip_blacklist.append(rip)
					else:
						#AZR
						loc = get_azr_loc(rip)
						if loc in ['koreasouth', 'koreacentral']:
							print(f'{rip} is AZR KR Server')
						else:
							if rip not in ip_whitelist:
								if rip not in ip_blacklist:
									subprocess.run(f'cports /close * * {rip} *')
									subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=in action=block remoteip={res["ip"]}')
									subprocess.run(f'netsh advfirewall firewall add rule name="r6kr" dir=out action=block remoteip={res["ip"]}')
									print(f'Blocked and dropped connection to: {rip}')
									ip_blacklist.append(rip)

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

refresh_db()

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

startMonitorBtn = tk.Button(window, text='방화벽 초기화', command=delete_firewalls)
startMonitorBtn.pack()

startMonitorBtn = tk.Button(window, text='데이터베이스 다시 다운로드', command=refresh_db)
startMonitorBtn.pack()

exitMonitorBtn = tk.Button(window, text='프로그램 종료', command=exit_program)
exitMonitorBtn.pack()

infoTextLabel = tk.Label(window, text=infoText)
infoTextLabel.pack()

window.mainloop()
