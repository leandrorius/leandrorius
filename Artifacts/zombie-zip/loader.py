#!/usr/bin/env python3
"""
Zombie ZIP Loader PoC - Fixed Version
"""

import struct
import zlib
import sys

def extract_and_save_payload(zip_path: str, output_path: str):
    """
    Extrai o payload real ignorando o método declarado e salvando em binário.
    """
    with open(zip_path, 'rb') as f:
        data = f.read()

    # Parse do cabeçalho local (Local File Header)
    sig = struct.unpack('<I', data[0:4])[0]
    if sig != 0x04034b50:
        raise ValueError("Arquivo não é um ZIP válido")

    # Extração de metadados para localizar os dados comprimidos
    method = struct.unpack('<H', data[8:10])[0]
    comp_size = struct.unpack('<I', data[18:22])[0]
    name_len = struct.unpack('<H', data[26:28])[0]
    extra_len = struct.unpack('<H', data[28:30])[0]

    # Localiza o início dos dados comprimidos (após o cabeçalho, nome e campos extras)
    data_offset = 30 + name_len + extra_len
    comp_data = data[data_offset:data_offset + comp_size]

    print(f"[*] Método declarado: {method}")
    print(f"[*] Tamanho comprimido: {comp_size} bytes")

    # A MÁGICA: Decomprime como DEFLATE puro (raw), ignorando o que o ZIP diz
    try:
        # O wbits=-15 indica raw DEFLATE (sem cabeçalhos zlib/gzip)
        payload_final = zlib.decompress(comp_data, -15)
        
        # SALVAMENTO CORRETO: Modo 'wb' e escrita direta da variável de bytes
        with open(output_path, 'wb') as f_out:
            f_out.write(payload_final)
            
        print(f"[+] Sucesso! Payload gravado em: {output_path}")
        
    except zlib.error as e:
        print(f"[-] Erro na descompressão: {e}")

if __name__ == "__main__":
    # Ajuste o nome do seu arquivo .zip de entrada aqui
    arquivo_zip = "method_mismatch.zip" 
    arquivo_saida = "eicar.com"
    
    try:
        extract_and_save_payload(arquivo_zip, arquivo_saida)
    except FileNotFoundError:
        print(f"[-] Erro: Arquivo {arquivo_zip} não encontrado.")
    except Exception as e:
        print(f"[-] Ocorreu um erro: {e}")
