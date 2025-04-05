# Scanner de Dispositivos MikroTik (MNDP)

Este script Python captura pacotes MNDP (MikroTik Neighbor Discovery Protocol) na rede e permite identificar dispositivos MikroTik, mesmo quando não possuem um endereço IP configurado.

## Requisitos

- Python 3.6 ou superior
- Biblioteca PyShark
- Permissões administrativas para captura de pacotes

## Instalação

1. Clone este repositório ou baixe os arquivos do projeto.

2. Instale as dependências necessárias:

```bash
pip install -r requirements.txt
```

3. Para sistemas Windows, é necessário ter o Wireshark instalado, pois o PyShark depende dele para captura de pacotes.

## Uso

### Listar interfaces de rede disponíveis

```bash
python scan_mikrotik.py -l
```

### Capturar em uma interface específica

```bash
python scan_mikrotik.py -i <nome_da_interface>
```

### Capturar em todas as interfaces disponíveis

```bash
python scan_mikrotik.py
```

## Como funciona

O script funciona da seguinte forma:

1. Captura pacotes UDP na porta 5678, que é utilizada pelo protocolo MNDP.
2. Analisa o conteúdo dos pacotes para extrair informações como:
   - Endereço MAC
   - Endereço IP (se disponível)
   - Nome do dispositivo (Identity)
   - Plataforma
   - Versão do sistema
3. Exibe as informações em tempo real quando um novo dispositivo é encontrado.
4. Ao finalizar (pressionar Ctrl+C), exibe um resumo de todos os dispositivos encontrados.

## Solução de problemas

- **Permissões**: O script precisa ser executado com permissões administrativas para capturar pacotes.
- **Não encontra dispositivos**: Verifique se está usando a interface de rede correta e se está na mesma rede dos dispositivos MikroTik.
- **Erro ao iniciar captura**: Verifique se o Wireshark está instalado corretamente (no caso do Windows).

## Licença

Este projeto é licenciado sob a licença MIT. 