import os
import ipaddress
import nmap
import threading
import platform
import sys
import subprocess


class ScannerAgressivo:
    def __init__(self):
        self.mikrotik_hosts = []
        self.lock = threading.Lock()
        self.nmap_path = self.verificar_nmap()

    def verificar_nmap(self):
        """Verifica se o nmap está instalado e retorna o caminho completo"""
        try:
            # Verifica se o nmap está disponível no PATH
            if platform.system() == "Windows":
                # Em Windows, procura nos locais típicos de instalação
                possivel_caminho = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
                if os.path.exists(possivel_caminho):
                    return possivel_caminho
                
                possivel_caminho = "C:\\Program Files\\Nmap\\nmap.exe"
                if os.path.exists(possivel_caminho):
                    return possivel_caminho
                
                # Tenta encontrar através de where no Windows
                try:
                    resultado = subprocess.check_output(['where', 'nmap'], stderr=subprocess.STDOUT, text=True).strip()
                    if os.path.exists(resultado.split('\n')[0]):
                        return resultado.split('\n')[0]
                except:
                    pass
            else:
                # Em sistemas Unix-like, tenta usar which
                try:
                    resultado = subprocess.check_output(['which', 'nmap'], stderr=subprocess.STDOUT, text=True).strip()
                    if os.path.exists(resultado):
                        return resultado
                except:
                    pass
            
            # Verifica se o comando nmap funciona diretamente
            subprocess.check_output(['nmap', '--version'], stderr=subprocess.STDOUT)
            return 'nmap'  # Nmap está no PATH
        except Exception as e:
            print(f"AVISO: Não foi possível localizar o executável do Nmap: {e}")
            print("Por favor, instale o Nmap e verifique se ele está no PATH do sistema.")
            print("Ou execute o script com o caminho completo: python scan.py /caminho/para/nmap")
            if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
                return sys.argv[1]
            return None

    def descobrir_ip_local(self):
        """
        Descobre o IP local da máquina, ignorando endereços APIPA (169.254.x.x) e interfaces virtuais
        """
        try:
            # Usa socket para encontrar um IP válido
            import socket
            
            # Primeiro método - conectar a um destino externo
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Não precisa realmente conectar a este endereço, só precisamos de uma "rota"
                s.connect(('8.8.8.8', 53))
                ip_local = s.getsockname()[0]
                s.close()
                
                # Verifica se é um endereço APIPA (169.254.x.x)
                if not ip_local.startswith('169.254.'):
                    print(f"IP encontrado (método socket): {ip_local}")
                    return ip_local
            except:
                s.close()
                
            # Segundo método - listar todos IPs e escolher o melhor
            possíveis_ips = []
            
            if platform.system() == "Windows":
                # Em Windows, usa ipconfig
                ipconfig = os.popen('ipconfig').read()
                for line in ipconfig.split('\n'):
                    if "IPv4" in line and "." in line:
                        ip = line.split(":")[-1].strip()
                        # Ignora endereços APIPA
                        if not ip.startswith('169.254.'):
                            possíveis_ips.append(ip)
            else:
                # Em Linux e outros sistemas Unix-like
                try:
                    hostname = os.popen('hostname -I').read().strip()
                    for ip in hostname.split():
                        if not ip.startswith('169.254.'):
                            possíveis_ips.append(ip)
                except:
                    pass
            
            # Método 3 - usar netifaces se disponível
            try:
                import netifaces
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            # Ignora loopback e APIPA
                            if not ip.startswith('127.') and not ip.startswith('169.254.'):
                                possíveis_ips.append(ip)
            except ImportError:
                # netifaces não está instalado, prossegue sem ele
                pass
            
            # Remove duplicatas e prioriza IPs
            possíveis_ips = list(set(possíveis_ips))
            
            # Prioriza endereços de redes locais comuns
            for prefixo in ['192.168.', '10.', '172.']:
                for ip in possíveis_ips:
                    if ip.startswith(prefixo):
                        print(f"IP encontrado (rede local): {ip}")
                        return ip
            
            # Se encontrou algum IP válido, usa o primeiro
            if possíveis_ips:
                print(f"IP encontrado (lista): {possíveis_ips[0]}")
                return possíveis_ips[0]
            
            # Se chegou aqui, não conseguiu encontrar um IP válido
            print("AVISO: Usando IP de loopback (127.0.0.1) por não conseguir detectar um IP válido.")
            print("Isso limita o escaneamento apenas à sua máquina local.")
            print("Verifique sua conexão de rede ou insira um IP manualmente.")
            return '127.0.0.1'
            
        except Exception as e:
            print(f"Erro ao detectar IP: {e}")
            print("AVISO: Usando IP de loopback (127.0.0.1) devido a um erro.")
            return '127.0.0.1'
            
    # Permite ao usuário especificar manualmente o IP de rede
    def perguntar_ip_manual(self):
        print("\nDeseja informar um IP manualmente? (s/n): ", end='')
        resposta = input().lower()
        if resposta == 's' or resposta == 'sim':
            print("Digite o IP da rede (ex: 192.168.1.0): ", end='')
            ip_manual = input().strip()
            try:
                # Validar o formato do IP
                ipaddress.ip_address(ip_manual)
                return ip_manual
            except:
                print("IP inválido. Usando IP detectado automaticamente.")
                return None
        return None
        
    def obter_rede_completa(self, ip):
        ip_rede = ipaddress.ip_network(f'{ip}/24', strict=False)
        return ip_rede

    def escanear_host(self, host):
        if not self.nmap_path:
            print(f"ERRO: Nmap não encontrado, impossível escanear {host}")
            return
            
        try:
            scanner = nmap.PortScanner(nmap_search_path=(self.nmap_path,))
            # Portas comumente abertas em dispositivos MikroTik
            scanner.scan(hosts=str(host), arguments='-p 8728,8291,22,80,443,161,23 --open -T4')

            if str(host) in scanner.all_hosts():
                # Verifica se alguma porta típica do MikroTik está aberta
                portas_encontradas = scanner[str(host)]['tcp'].keys() if 'tcp' in scanner[str(host)] else []
                portas_mikrotik = [8291, 8728]  # Portas específicas do MikroTik
                
                # Se alguma porta específica do MikroTik está aberta, provavelmente é um MikroTik
                if any(porta in portas_encontradas for porta in portas_mikrotik):
                    with self.lock:
                        self.mikrotik_hosts.append(str(host))
                        print(f'Equipamento MikroTik possivelmente encontrado: {host}')
        except Exception as e:
            print(f"Erro ao escanear {host}: {e}")

    def escanear_dispositivos(self, ip_rede):
        if not self.nmap_path:
            print("ERRO: Nmap não encontrado. Impossível prosseguir com o escaneamento.")
            return
            
        threads = []
        print(f"Iniciando escaneamento da rede {ip_rede}...")
        print(f"Total de IPs a serem escaneados: {ip_rede.num_addresses - 2}")  # Exclui endereço de rede e broadcast
        print(f"Usando nmap em: {self.nmap_path}")

        for ip in ip_rede.hosts():
            t = threading.Thread(target=self.escanear_host, args=(ip,))
            threads.append(t)
            t.start()
            
            # Limita o número de threads paralelas para evitar sobrecarga
            if len(threads) >= 50:
                for t in threads[:10]:
                    t.join()
                threads = threads[10:]

        # Aguarda as threads restantes terminarem
        for t in threads:
            t.join()

    def executar(self):
        print("Iniciando Scanner de Equipamentos MikroTik...")
        
        if not self.nmap_path:
            print("Escaneamento cancelado. Instale o Nmap e tente novamente.")
            return
            
        ip_local = self.descobrir_ip_local()
        print(f'IP Local detectado: {ip_local}')

        if not ip_local or ip_local == '127.0.0.1':
            print("Não foi possível detectar um IP válido de rede. Por favor, verifique sua conexão.")
            return

        ip_rede = self.obter_rede_completa(ip_local)
        print(f'Rede a ser escaneada: {ip_rede}')
        
        print("Iniciando escaneamento automático...")
        self.escanear_dispositivos(ip_rede)

        if self.mikrotik_hosts:
            print('\nDispositivos MikroTik encontrados:')
            for host in self.mikrotik_hosts:
                print(f'- {host}')
        else:
            print('\nNenhum dispositivo MikroTik encontrado na rede.')
        
        print("\nEscaneamento concluído.")


if __name__ == '__main__':
    scanner = ScannerAgressivo()
    scanner.executar()
