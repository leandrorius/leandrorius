"""
SCRIPT DE CONSULTA DE HASHES NO VIRUSTOTAL

Esse script consulta uma hash na api do Virustotal, pesquisa se alguma fonte de threat intel classificou como malicioso, e gera um relatório trazendo também o package name (focado em android)

UTILIZAÇÃO:
Crie um arquivo chamado hashlist.txt no mesmo diretório do script. Após executado o script, o relatório será gerado em output.txt no formato:
DATAHORA;HASH;PACKAGENAME;MALICIOSO/LIMPO

Desenvolvido por Leandro Alves

"""




import requests
import json
import time
import os
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)




def checkHash(inputhash):
    arquivo_saida = open("output.txt", "a") 

    url = "https://www.virustotal.com/api/v3/files/"+inputhash

    payload={}
    headers = {
    'X-Apikey': 'COLOQUE SUA API KEY AQUI'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    response_json = response.json()

    saida = json.loads(response.text) # saida em dicionario
      
    try:
        packageName = saida['data']['attributes']['androguard']['Package']
    except:
        packageName = "NOT FOUND"

    
    result_threat = saida['data']['attributes']['last_analysis_results']

    for fonteThreat in result_threat: # Para cada fonte de threat intel no resultado:
        now=datetime.datetime.now()
        category = result_threat[fonteThreat]['category']
        result = result_threat[fonteThreat]['result']
        #print (f"{fonteThreat}, {category}, {result}")
        if (category != "harmless" and category != "undetected"):
            print (f"ALERTA! Threat intel {fonteThreat} indicou categoria {category} para hash {inputhash}")
            arquivo_saida.write(f"{now};{inputhash};{packageName};Malicioso\n")
            arquivo_saida.close()
            return True
            
        if (result != 'clean' and result != 'unrated' and result != 'null' and result != 'None' and not result is None):
            print (f"ALERTA! Threat intel {fonteThreat} indicou resultado {result} para hash {inputhash}")
            arquivo_saida.write(f"{now};{inputhash};{packageName};Malicioso\n")
            arquivo_saida.close()
            return True

    print (f"IP {inputhash} limpo")
    arquivo_saida.write(f"{now}{inputhash};{packageName};Limpo\n")
    arquivo_saida.close()
    return False
    


with open("hashlist.txt", newline="\n") as listaHash:
    for inputhash in listaHash:
        now=datetime.datetime.now()
        inputhash = inputhash.strip()
        retorno = checkHash(inputhash)
        #print (f"{now} - {inputhash} - {retorno}")
        time.sleep(5)

