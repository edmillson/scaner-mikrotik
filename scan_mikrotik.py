#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script aprimorado para descoberta de dispositivos MikroTik usando o protocolo MNDP.

Este script implementa uma análise detalhada dos pacotes MNDP (MikroTik Neighbor Discovery Protocol)
para identificar dispositivos MikroTik na rede, mesmo sem IP configurado.
"""

from scapy.all import *
import logging
import sys
import struct
import binascii
import threading
import time
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('scan_mikrotik')

# Dicionário para armazenar os dispositivos encontrados
dispositivos_encontrados = {}
# Lock para acesso thread-safe ao dicionário de dispositivos
dispositivos_lock = threading.Lock()

# Tempo máximo padrão de execução (em segundos)
TEMPO_MAXIMO_EXECUCAO = 30

# Lista de prefixos MAC de fabricantes MikroTik
MIKROTIK_MAC_PREFIXES = [
    '00:0C:42',
    '6C:3B:6B',
    'D4:CA:6D',
    'CC:2D:E0',
    'E4:8D:8C',
    '48:8F:5A',
    '74:4D:28',
    'B8:69:F4'
]

# Pré-compilar lista de prefixos em formato uppercase para comparação mais rápida
MIKROTIK_MAC_PREFIXES_UPPER = [prefix.upper() for prefix in MIKROTIK_MAC_PREFIXES]

# Tipos de dados no protocolo MNDP
MNDP_TYPES = {
    1: "MAC",
    5: "Identity",
    7: "Version",
    8: "Platform",
    10: "Uptime",
    11: "SoftwareID",
    12: "Board",
    14: "Unpack",
    15: "IPv6-Address",
    16: "Interface",
    17: "Username"
}

def is_mikrotik_device(mac_address):
    """
    Verifica se um endereço MAC pertence a um dispositivo MikroTik
    baseado nos prefixos MAC conhecidos.
    
    Args:
        mac_address: Endereço MAC em formato string (xx:xx:xx:xx:xx:xx)
        
    Returns:
        bool: True se for um dispositivo MikroTik, False caso contrário
    """
    mac_prefix = mac_address.upper()[:8]  # Obtem os 3 primeiros octetos (xx:xx:xx)
    return mac_prefix in MIKROTIK_MAC_PREFIXES_UPPER

def parse_mndp_packet(data):
    """
    Realiza o parsing detalhado de um pacote MNDP.
    
    Args:
        data: Dados brutos do pacote
        
    Returns:
        dict: Dicionário com os campos extraídos
    """
    result = {}
    
    # Verificar se temos dados suficientes
    if len(data) < 4:
        return result
    
    pos = 0
    
    # Tentar extrair TLVs (Type-Length-Value)
    while pos + 4 < len(data):
        try:
            # Extrair tipo (2 bytes) e tamanho (2 bytes)
            tlv_type = struct.unpack("<H", data[pos:pos+2])[0]
            tlv_length = struct.unpack("<H", data[pos+2:pos+4])[0]
            
            # Verificar se o tamanho é válido
            if pos + 4 + tlv_length > len(data):
                break
            
            # Extrair valor
            tlv_value = data[pos+4:pos+4+tlv_length]
            
            # Registrar campo conhecido
            if tlv_type in MNDP_TYPES:
                tipo_nome = MNDP_TYPES[tlv_type]
                
                # Decodificar valor com base no tipo
                if tlv_type == 1:  # MAC
                    result[tipo_nome] = ':'.join([f'{b:02x}' for b in tlv_value])
                elif tlv_type == 15:  # IPv6
                    result[tipo_nome] = ':'.join([f'{tlv_value[i:i+2].hex()}' for i in range(0, len(tlv_value), 2)])
                else:  # Outros tipos como texto
                    try:
                        # Tentar decodificar como texto
                        texto = tlv_value.decode('utf-8', errors='replace')
                        result[tipo_nome] = texto
                    except:
                        # Caso falhe, usar representação hex
                        result[tipo_nome] = tlv_value.hex()
            
            # Avançar para o próximo TLV
            pos += 4 + tlv_length
            
        except Exception as e:
            logger.debug(f"Erro ao processar TLV: {e}")
            break
    
    return result

def processar_pacote(pacote):
    """
    Processa pacotes UDP na porta 5678 (MNDP) usando decodificação detalhada.
    
    Args:
        pacote: Pacote Scapy capturado
    """
    try:
        # Verificar se é um pacote UDP na porta 5678 (MNDP)
        if UDP in pacote and (pacote[UDP].dport == 5678 or pacote[UDP].sport == 5678):
            
            # Extrair endereço MAC do pacote Ethernet
            mac_address = pacote[Ether].src
            
            # Verificar se o MAC corresponde a um dispositivo MikroTik
            is_mikrotik = is_mikrotik_device(mac_address)
            
            # Inicializar valores
            ip_address = "N/A"
            identity = "N/A"
            platform = "N/A"
            version = "N/A"
            
            # Tentar obter o IP do dispositivo, se disponível
            if IP in pacote:
                ip_address = pacote[IP].src
            
            # Analisar dados do pacote UDP
            info_mndp = {}
            if Raw in pacote:
                dados_raw = bytes(pacote[Raw])
                logger.debug(f"Dados brutos do pacote: {dados_raw.hex()}")
                
                # Realizar parsing detalhado do pacote MNDP
                info_mndp = parse_mndp_packet(dados_raw)
                
                # Se encontrarmos informações MNDP, vamos usá-las
                if info_mndp:
                    if "Identity" in info_mndp:
                        identity = info_mndp["Identity"]
                    if "Platform" in info_mndp:
                        platform = info_mndp["Platform"]
                    if "Version" in info_mndp:
                        version = info_mndp["Version"]
                    
                    # Exibir todas as informações em modo debug
                    for key, value in info_mndp.items():
                        logger.debug(f"MNDP {key}: {value}")
                        
                    # Se encontramos informações MNDP, é provavelmente um MikroTik
                    is_mikrotik = True
            
            # Se é um dispositivo MikroTik, registrar e exibir informações
            if is_mikrotik:
                with dispositivos_lock:
                    dispositivo_novo = mac_address not in dispositivos_encontrados
                    
                    if dispositivo_novo:
                        dispositivos_encontrados[mac_address] = {
                            'ip': ip_address,
                            'identity': identity,
                            'platform': platform,
                            'version': version,
                            'last_seen': datetime.now(),
                            'raw_data': info_mndp,
                            'detected_by': 'MAC Prefix' if is_mikrotik_device(mac_address) else 'MNDP Protocol'
                        }
                        
                        logger.info(f"Novo dispositivo MikroTik encontrado!")
                        logger.info(f"MAC: {mac_address}")
                        logger.info(f"IP: {ip_address}")
                        logger.info(f"Detectado por: {'MAC Prefix' if is_mikrotik_device(mac_address) else 'MNDP Protocol'}")
                        
                        if info_mndp:
                            for key, value in info_mndp.items():
                                if key not in ["MAC"] and value:  # Evitar duplicar informações
                                    logger.info(f"{key}: {value}")
                        else:
                            if identity != "N/A":
                                logger.info(f"Identity: {identity}")
                            if platform != "N/A":
                                logger.info(f"Platform: {platform}")
                            if version != "N/A":
                                logger.info(f"Version: {version}")
                        
                        logger.info("-" * 50)
                    else:
                        # Atualizar informações do dispositivo encontrado
                        dispositivos_encontrados[mac_address]['last_seen'] = datetime.now()
                        if dispositivos_encontrados[mac_address]['ip'] == "N/A" and ip_address != "N/A":
                            dispositivos_encontrados[mac_address]['ip'] = ip_address
                            logger.info(f"IP atualizado para dispositivo {mac_address}: {ip_address}")
    
    except Exception as e:
        logger.error(f"Erro ao processar pacote: {e}")

def enviar_mndp_request_para_rede(network, interface=None):
    """
    Envia pacotes MNDP para uma rede específica.
    
    Args:
        network: Rede no formato "192.168.1.0/24"
        interface: Interface de rede para envio
    """
    try:
        # Extrair informações da rede
        net_addr, net_mask = network.split('/')
        net_mask = int(net_mask)
        
        # Calcular número de hosts na rede
        num_hosts = 2**(32 - net_mask) - 2
        
        # Limitar o número de hosts para evitar sobrecarga
        if num_hosts > 254:
            logger.info(f"Rede {network} é muito grande, limitando a 254 hosts")
            num_hosts = 254
        
        # Criar base de endereço IP
        ip_base = socket.inet_aton(net_addr)
        ip_base_int = struct.unpack('!I', ip_base)[0] & ((2**32 - 1) << (32 - net_mask))
        
        # Criar e enviar pacotes
        for i in range(1, num_hosts + 1):
            # Calcular próximo IP
            ip_int = ip_base_int + i
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            
            # Criar pacote MNDP
            eth = Ether(dst="ff:ff:ff:ff:ff:ff")
            ip_pkt = IP(dst=ip)
            udp = UDP(sport=5678, dport=5678)
            raw = Raw(load=b"\x00\x00")
            
            pacote = eth/ip_pkt/udp/raw
            
            # Enviar pacote
            if interface:
                sendp(pacote, iface=interface, verbose=0)
            else:
                sendp(pacote, verbose=0)
            
    except Exception as e:
        logger.error(f"Erro ao enviar pacote MNDP para rede {network}: {e}")

def enviar_mndp_request(interface=None, redes=None):
    """
    Envia pacotes MNDP para solicitar respostas de dispositivos MikroTik.
    
    Args:
        interface: Interface de rede para envio
        redes: Lista de redes para enviar pacotes (formato: ["192.168.1.0/24", "10.0.0.0/24"])
    """
    try:
        # Se não foram especificadas redes, enviar broadcast
        if not redes:
            # Criar um pacote MNDP simples
            eth = Ether(dst="ff:ff:ff:ff:ff:ff")
            ip = IP(dst="255.255.255.255")
            udp = UDP(sport=5678, dport=5678)
            # Pacote vazio é suficiente para despertar respostas
            raw = Raw(load=b"\x00\x00")
            
            pacote = eth/ip/udp/raw
            
            logger.info("Enviando pacote de descoberta MNDP via broadcast...")
            
            # Enviar o pacote várias vezes para aumentar a chance de resposta
            for _ in range(2):
                if interface:
                    sendp(pacote, iface=interface, verbose=0)
                else:
                    sendp(pacote, verbose=0)
                time.sleep(0.5)
        else:
            # Enviar para redes específicas
            logger.info(f"Enviando pacotes MNDP para {len(redes)} redes...")
            
            # Criar pool de threads para envio paralelo
            with ThreadPoolExecutor(max_workers=min(10, len(redes))) as executor:
                for rede in redes:
                    executor.submit(enviar_mndp_request_para_rede, rede, interface)
            
    except Exception as e:
        logger.error(f"Erro ao enviar pacote MNDP: {e}")

def descobrir_redes_locais():
    """
    Descobre as redes locais disponíveis.
    
    Returns:
        list: Lista de redes no formato CIDR
    """
    redes = []
    try:
        # Obter interfaces com IPv4
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                # Verificar se é um IP válido (não loopback, não 0.0.0.0)
                if ip and ip.startswith(('192.168.', '10.', '172.')) and ip != '0.0.0.0':
                    # Assumir máscara /24 para simplificar
                    # Em uma implementação mais robusta, deveríamos obter a máscara real
                    ip_base = '.'.join(ip.split('.')[:3]) + '.0'
                    redes.append(f"{ip_base}/24")
            except:
                continue
    except Exception as e:
        logger.error(f"Erro ao descobrir redes: {e}")
    
    if not redes:
        # Adicionar redes padrão se não encontrar nenhuma
        redes = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
    
    return redes

def iniciar_captura(interface=None, tempo_execucao=TEMPO_MAXIMO_EXECUCAO):
    """
    Inicia a captura de pacotes MNDP na interface especificada.
    
    Args:
        interface: A interface de rede para captura.
        tempo_execucao: Tempo máximo de execução em segundos
    """
    # Filtro para pacotes UDP na porta 5678
    filtro_bpf = "udp port 5678"
    
    logger.info(f"Iniciando captura de pacotes MNDP na porta 5678...")
    logger.info(f"Tempo máximo de execução: {tempo_execucao} segundos")
    logger.info(f"Pressione Ctrl+C para interromper a captura")
    
    # Variável para controlar o término da captura
    stop_sniff = threading.Event()
    
    def parar_apos_timeout():
        time.sleep(tempo_execucao)
        stop_sniff.set()
        logger.info(f"\nTempo limite de {tempo_execucao} segundos atingido, finalizando captura...")
    
    # Thread para interromper a captura após o tempo limite
    timer_thread = threading.Thread(target=parar_apos_timeout)
    timer_thread.daemon = True
    timer_thread.start()
    
    try:
        # Iniciar a captura com stop_filter para parar quando o evento for definido
        if interface:
            logger.info(f"Capturando na interface: {interface}")
            sniff(filter=filtro_bpf, prn=processar_pacote, iface=interface, 
                 store=0, stop_filter=lambda _: stop_sniff.is_set())
        else:
            logger.info("Capturando em todas as interfaces disponíveis")
            sniff(filter=filtro_bpf, prn=processar_pacote, 
                 store=0, stop_filter=lambda _: stop_sniff.is_set())
            
    except KeyboardInterrupt:
        logger.info("\nCaptura interrompida pelo usuário")
    except Exception as e:
        logger.error(f"Erro durante a captura: {e}")
    finally:
        # Resumo dos dispositivos encontrados
        exibir_resumo()

def exibir_resumo():
    """Exibe um resumo de todos os dispositivos MikroTik encontrados durante a captura."""
    logger.info("\n" + "=" * 60)
    logger.info("RESUMO DOS DISPOSITIVOS MIKROTIK ENCONTRADOS")
    logger.info("=" * 60)
    
    if not dispositivos_encontrados:
        logger.info("Nenhum dispositivo MikroTik foi encontrado durante a captura.")
        return
    
    for idx, (mac, info) in enumerate(dispositivos_encontrados.items(), 1):
        logger.info(f"Dispositivo {idx}:")
        logger.info(f"  MAC: {mac}")
        logger.info(f"  IP: {info['ip']}")
        logger.info(f"  Detectado por: {info.get('detected_by', 'MNDP Protocol')}")
        
        # Exibir dados MNDP se disponíveis
        if 'raw_data' in info and info['raw_data']:
            for key, value in info['raw_data'].items():
                if key not in ["MAC"] and value:  # Evitar duplicar informações
                    logger.info(f"  {key}: {value}")
        else:
            logger.info(f"  Identity: {info['identity']}")
            logger.info(f"  Platform: {info['platform']}")
            logger.info(f"  Version: {info['version']}")
            
        logger.info(f"  Último avistamento: {info['last_seen'].strftime('%H:%M:%S')}")
        logger.info("-" * 60)

def listar_interfaces():
    """Lista todas as interfaces de rede disponíveis para captura."""
    try:
        interfaces = get_if_list()
        logger.info("Interfaces de rede disponíveis:")
        for idx, interface in enumerate(interfaces, 1):
            logger.info(f"{idx}. {interface}")
        return interfaces
    except Exception as e:
        logger.error(f"Erro ao listar interfaces: {e}")
        return []

if __name__ == "__main__":
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description='Scanner de dispositivos MikroTik via protocolo MNDP')
    parser.add_argument('-i', '--interface', help='Interface de rede para captura')
    parser.add_argument('-l', '--list-interfaces', action='store_true', help='Listar interfaces disponíveis')
    parser.add_argument('-d', '--debug', action='store_true', help='Ativar modo de depuração')
    parser.add_argument('-a', '--active', action='store_true', help='Modo ativo: envia pacotes MNDP para solicitar respostas')
    parser.add_argument('-t', '--tempo', type=int, default=TEMPO_MAXIMO_EXECUCAO, help=f'Tempo máximo de execução em segundos (padrão: {TEMPO_MAXIMO_EXECUCAO})')
    parser.add_argument('-r', '--redes', nargs='+', help='Redes para escanear (formato: 192.168.1.0/24)')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    if args.list_interfaces:
        listar_interfaces()
    else:
        # Se o modo ativo estiver habilitado, enviar pacotes MNDP antes de iniciar a captura
        if args.active:
            # Se foram especificadas redes, usar essas redes
            # Caso contrário, tentar descobrir redes locais
            redes_para_escanear = args.redes if args.redes else descobrir_redes_locais()
            logger.info(f"Escaneando as seguintes redes: {', '.join(redes_para_escanear)}")
            enviar_mndp_request(args.interface, redes_para_escanear)
        
        # Iniciar captura com tempo limitado
        iniciar_captura(args.interface, args.tempo) 