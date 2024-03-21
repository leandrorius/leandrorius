import requests
import json
import time
import os

def checkIP(ip, delay=16):
    arquivo_saida = open("saida2.txt", "a") 

    url = "https://www.virustotal.com/api/v3/ip_addresses/"+ip
    payload={}
    headers = {
    'X-Apikey': '[API KEY]'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    response_json = response.json()

    saida = json.loads(response.text) # saida em dicionario

    try:
        ownerIP = saida['data']['attributes']['as_owner']
    except:
        ownerIP = "UNKNOWN"
    country = saida['data']['attributes']['country']
    result_threat = saida['data']['attributes']['last_analysis_results']

    for fonteThreat in result_threat: # Para cada fonte de threat intel no resultado:
        category = result_threat[fonteThreat]['category']
        result = result_threat[fonteThreat]['result']
        # print (f"{fonteThreat}, {category}, {result}")
        if (category != "harmless" and category != "undetected"):
            print (f"ALERTA! Threat intel {fonteThreat} indicou categoria {category} para IP {ip}")
            arquivo_saida.write(f"{ip};{ownerIP};{country};Malicioso\n")
            arquivo_saida.close()
            return True
            
        if (result != 'clean' and result != 'unrated'):
            print (f"ALERTA! Threat intel {fonteThreat} indicou resultado {result} para IP {ip}")
            arquivo_saida.write(f"{ip};{ownerIP};{country};Malicioso\n")
            arquivo_saida.close()
            return True

    print (f"IP {ip} limpo")
    arquivo_saida.write(f"{ip};{ownerIP};{country};Limpo\n")
    arquivo_saida.close()
    return False
    


with open("ip list.txt", newline="\n") as listaIP:
    for ip in listaIP:
        ip = ip.strip()
        retorno = checkIP(ip)
        print (f"{ip} - {retorno}")
        time.sleep(20)

