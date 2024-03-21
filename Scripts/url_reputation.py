import requests
import json
import time
import os
import base64

def checkIP(ip, URL, delay=16):
    arquivo_saida = open("saidaurl.txt", "a") 

    url = "https://www.virustotal.com/api/v3/urls/"+ip

    payload={}
    headers = {
    'X-Apikey': '[API KEY]]'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    response_json = response.json()

    saida = json.loads(response.text) # saida em dicionario




    try:
        ownerIP = saida['data']['attributes']['as_owner']
    except:
        ownerIP = "UNKNOWN"
    country = "NA"
    result_threat = saida['data']['attributes']['last_analysis_results']

    for fonteThreat in result_threat: # Para cada fonte de threat intel no resultado:
        category = result_threat[fonteThreat]['category']
        result = result_threat[fonteThreat]['result']
        # print (f"{fonteThreat}, {category}, {result}")
        if (category != "harmless" and category != "undetected"):
            print (f"ALERTA! Threat intel {fonteThreat} indicou categoria {category} para URL {URL}")
            arquivo_saida.write(f"{ip};{ownerIP};{country};Malicioso\n")
            arquivo_saida.close()
            return True
            
        if (result != 'clean' and result != 'unrated'):
            print (f"ALERTA! Threat intel {fonteThreat} indicou resultado {result} para URL {URL}")
            arquivo_saida.write(f"{ip};{ownerIP};{country};Malicioso\n")
            arquivo_saida.close()
            return True

    print (f"URL {URL} limpo")
    arquivo_saida.write(f"{URL};{ownerIP};{country};Limpo\n")
    arquivo_saida.close()
    return False
    


with open("url list.txt", newline="\n") as listaURL:
    for URL in listaURL:

        url_id = base64.urlsafe_b64encode(URL.encode()).decode().strip("=")
        retorno = checkIP(url_id, URL)
        print (f"{URL} - {retorno}")
        time.sleep(20)

