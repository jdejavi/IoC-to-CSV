#!/bin/env python3

#Programa hecho por Javier Matilla aka m4t1
#Modo de uso: python3 IoC_to_CSV.py iocs.txt
#Espero que os sirva! :)))

banner = """
 ██▓▒█████  ▄████▄     ▄▄▄█████▓▒█████      ▄████▄   ████████▒   █▓
▓██▒██▒  ██▒██▀ ▀█     ▓  ██▒ ▓▒██▒  ██▒   ▒██▀ ▀█ ▒██    ▓██░   █▒
▒██▒██░  ██▒▓█    ▄    ▒ ▓██░ ▒▒██░  ██▒   ▒▓█    ▄░ ▓██▄  ▓██  █▒░
░██▒██   ██▒▓▓▄ ▄██▒   ░ ▓██▓ ░▒██   ██░   ▒▓▓▄ ▄██▒ ▒   ██▒▒██ █░░
░██░ ████▓▒▒ ▓███▀ ░     ▒██▒ ░░ ████▓▒░   ▒ ▓███▀ ▒██████▒▒ ▒▀█░  
░▓ ░ ▒░▒░▒░░ ░▒ ▒  ░     ▒ ░░  ░ ▒░▒░▒░    ░ ░▒ ▒  ▒ ▒▓▒ ▒ ░ ░ ▐░  
 ▒ ░ ░ ▒ ▒░  ░  ▒          ░     ░ ▒ ▒░      ░  ▒  ░ ░▒  ░ ░ ░ ░░  
 ▒ ░ ░ ░ ▒ ░             ░     ░ ░ ░ ▒     ░       ░  ░  ░     ░░  
 ░     ░ ░ ░ ░                     ░ ░     ░ ░           ░      ░  
           ░                               ░                   ░   
"""
import vt
import requests
import time
from sys import *
import re

#Variables GLOBALES
API_KEY = "[API_KEY]"

archivo_iocs = argv[1]

#Expresión regular que encuentra direcciones IPv4
regex_ip = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

#Expresión regular que encuentra urls
regex_url = r'https?://\S+'

archivo_salida = 'listaIoCs.csv'

#Declaramos los headers para la petición
headers = {
        'x-apikey': API_KEY
}
print(banner)
with open(archivo_salida, 'w') as arch_salida:
	arch_salida.write('Type,Object,Description' + '\n')

with open(archivo_iocs, 'r') as archivo:
	for ioc in archivo:
		ioc_clean = ioc.strip()
		print(f'[!] Se va a tratar el IoC --> {ioc_clean}')

		#Comprobación para ver si es una URL
		if re.search(regex_url,ioc_clean):
                        url = re.findall(regex_url, ioc_clean)
                        cadena = f'url,{url[0]}, Malicious URL'
                        with open(archivo_salida, 'a') as arch_salida:
                                arch_salida.write(cadena + '\n')
                        print(f'[*] Metido en el archivo de salida la IP --> {url[0]}')
                        print('\n\n')

		#Comprobación para ver si es una IP
		if re.search(regex_ip,ioc_clean):
			dir_ip = re.findall(regex_ip, ioc_clean)
			cadena = f'ip,{dir_ip[0]},'
			with open(archivo_salida, 'a') as arch_salida:
				arch_salida.write(cadena + '\n')
			print(f'[*] Metido en el archivo de salida la IP --> {dir_ip[0]}')
			print('\n\n')

		#Si es un hash se comprueba contra la API de VT
		url = f'https://www.virustotal.com/api/v3/files/{ioc_clean}'
		response = requests.get(url, headers=headers)
		if response.status_code == 200:
			data = response.json()
			sha256 = data['data']['attributes']['sha256']
			if 'data' in data and 'attributes' in data['data'] and 'crowdsourced_yara_results' in data['data']['attributes']:
        			yara_results = data['data']['attributes']['crowdsourced_yara_results']
        			for result in yara_results:
            				rule_name = result.get('rule_name')
			if 'meaningful_name' in data['data']['attributes']:
				exe_name = data['data']['attributes']['meaningful_name']
			else:
				exe_name = sha256

			cadena = f'sha256,{sha256},{exe_name} - {rule_name}'
			with open(archivo_salida, 'a') as arch_salida:
				arch_salida.write(cadena + '\n')
			print(f'[*] IoC --> {ioc_clean} almacenado en archivo salida')
			time.sleep(10)
			print('\n\n')
		else:
			print('Error, te jodes por feo')
