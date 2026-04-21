# Laboratório: Defesa de Perímetro e Análise de Tráfego com Scapy

Neste laboratório, simularemos um ambiente de rede simplificado onde o tráfego legítimo e malicioso coexistem. O objetivo é compreender a fundo a pilha de protocolos TCP/IP e aprender a utilizar ferramentas de inspeção de pacotes.

---

## Topologia da Rede
O ambiente é composto por quatro nós principais:
* **Cliente:** Gera tráfego legítimo para os serviços.
* **Servidor:** Hospeda Telnet (23), HTTP/Nginx (80) e MariaDB (3306).
* **Agente Malicioso:** Injeta pacotes de ataque com IPs variáveis.
* **Roteador:** O ponto central de monitoramento onde sua defesa será implementada.

![img](https://i.imgur.com/XpkDANY.png)
---

Um Agente Malicioso está operando na rede. Ele altera seu endereço IP constantemente e utiliza portas aleatórias (técnica de IP Spoofing e Port Hopping).

**Seu Objetivo:** Criar um script em Python utilizando a biblioteca Scapy que rode no Roteador. Este script deve:
* Analisar o conteúdo (payload) dos pacotes em tempo real.
* Identificar o ataque através de um padrão de assinatura (uma string ou comando específico que o malfeitor envia).
* Impedir o ataque ou alertar o administrador sem bloquear o IP ou a porta, pois estes são dinâmicos e mudariam em segundos.

## 3. Ferramentas de Sniffing e Análise

Antes de construir sua defesa, você deve aprender a analisar a rede.
O tcpdump é seu binóculo. Ele mostra o que está passando. O ngrep é seu detector de metais, focado em encontrar padrões de texto.

Uma ferramenta de **sniffing** (ou analisador de pacotes) funciona como um "grampo" digital, interceptando e registrando o tráfego que passa por uma interface de rede. Elas são essenciais para o diagnóstico de problemas de conexão, auditoria de segurança e estudo de protocolos, pois permitem visualizar exatamente o que está sendo transmitido entre dois pontos. Normalmente, essas ferramentas operam colocando a placa de rede em **modo promíscuo**, o que permite capturar pacotes mesmo que o destino final não seja a máquina que está monitorando, sendo frequentemente desenvolvidas em linguagens como **C** (pela performance de baixo nível) ou **Python** (pela flexibilidade na análise de dados).

Ferramentas de Snifing
- [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [wireshark](https://www.wireshark.org/docs/)
- [ngrep](https://linux.die.net/man/8/ngrep)


### TCPDUMP

O tcpdump é a ferramenta de linha de comando para captura de pacotes. Em ambientes de servidor ou containers (onde não há interface gráfica), ele é o padrão para capturar tudo o que acontece na rede e o salva em um arquivo de extensão .pcap (Packet Capture).

```bash
tcpdump -i any -w /app/laboratorio.pcap
```

- **-i any**: Escuta em todas as interfaces de rede do roteador.
- **-w**: Escreve (salva) o resultado em um arquivo para análise posterior em outras ferramentas.

Além de gravar o tráfego total, o tcpdump permite aplicar filtros em tempo real para capturar apenas pacotes específicos. Isso é essencial em redes com muito tráfego. Por exemplo, filtrar por Porta Específica. Útil para monitorar apenas um serviço (ex: apenas tráfego Web ou apenas Banco de Dados).

```bash
# Escuta apenas o tráfego na porta 80 (HTTP)
tcpdump -i any port 80
```

Filtrar por Endereço IP. Ideal para isolar o que um cliente específico está fazendo ou o que está chegando em um servidor.

```bash
# Captura apenas pacotes que tenham o IP 10.0.2.2 como origem ou destino
tcpdump -i any host 10.0.2.2
```

Filtrar por Origem e Destino (Fluxo Direcionado). Para ser ainda mais específico e ver apenas o que sai de um ponto A para um ponto B.

```bash
# Captura pacotes que saem do Cliente (src) para o Servidor (dst)
tcpdump -i any src 10.0.2.2 and dst 10.0.1.2
```


### NGREP

O ngrep (Network Grep) aplica a lógica de busca de texto do comando grep diretamente nos pacotes que estão trafegando na placa de rede em tempo real. Ele combina a capacidade de captura do tcpdump com a facilidade de busca de texto do comando grep. Ele permite que você escute a rede e filtre apenas os pacotes que contêm palavras-chave específicas.

Comando Principal (Monitoramento de Telnet).
```bash
ngrep -q -W byline port 23
```
- **-q (Quiet)**: Oculta os caracteres de controle e metadados irrelevantes, focando apenas no conteúdo útil.
- **-W byline**: Formata a saída quebrando as linhas de forma legível, simulando como o texto aparece na tela do usuário.
- **port 23**: Filtra o tráfego do protocolo Telnet.

Perceba que é possível visualizar o tráfego e captrar o login e senha de usuário.

Captura de Padrões Específicos (Filtro de Conteúdo).
```bash
# Busca apenas requisições GET na porta 80
ngrep -q -W byline "^GET" port 80

# Busca qualquer pacote que contenha a palavra "aluno" ou "lab123"
ngrep -i "aluno|lab123" any
```
- **"^GET"**: Usa expressões regulares para identificar o início de uma requisição web.
- **-i**: Ignora a diferença entre maiúsculas e minúsculas (case-insensitive).



### Wireshark
O Wireshark é a ferramenta da análise de redes com interface gráfica. Enquanto o tcpdump e o ngrep nos dão recortes rápidos no terminal, o Wireshark nos oferece o "Raio-X" completo de toda a comunicação. No nosso laboratório, como os containers não possuem interface gráfica, utilizamos a estratégia de capturar o tráfego no roteador e exportar o arquivo .pcap para análise na nossa máquina real.

Ao iniciar o Wireshark, a primeira coisa que fazemos é carregar o arquivo que gravamos anteriormente. Diferente de um editor de texto, o Wireshark entende a estrutura binária dos pacotes e já os organiza cronologicamente.

![wiwreshark](https://i.imgur.com/qDw02Oo.png)

A força do Wireshark está na sua organização em três seções principais, que permitem navegar do geral para o específico:


1. Lista de Pacotes (Topo): Cada linha é um pacote. As cores ajudam a identificar o protocolo (ex: azul para DNS, verde para HTTP, roxo para TCP).

2. Detalhes do Pacote (Meio): O Wireshark decodifica as camadas (Ethernet, IP, TCP) e permite que você abra cada uma para ver os campos, como endereços e portas.

3. Bytes do Pacote (Base): Mostra o dado bruto em hexadecimal e ASCII. É a prova final do que realmente passou pelo fio.

Como o TCP envia dados em muitos pacotes pequenos, ler um por um é difícil. A função Follow TCP Stream recria a conversa inteira em uma única janela, como se fosse um chat.


![fluxo-tcp](https://i.imgur.com/iMFVTgG.png)

Para fazer isso, clicamos com o botão direito em um pacote MariaDB e selecionamos Follow -> TCP Stream.

Ao abrir o fluxo TCP do MariaDB, a vulnerabilidade do protocolo fica exposta. O Wireshark exibe em cores diferentes o que o cliente enviou e o que o servidor respondeu. Conseguimos ver as queries envidas do cliente para servidor

![fluxo-tcp2](https://i.imgur.com/u6q0NXR.png)

### Scapy

Scapy é uma ferramenta poderosa para análise e manipulação de pacotes de rede. Através dela conseguimos criar as ferramentas sniffers como wireshark e similares.

Normalmente, quando um pacote chega na placa de rede, o Kernel do Linux faz todo o trabalho. Ele abre a camada Ethernet, depois a IP, depois a TCP e entrega apenas o "conteúdo" (o dado) para o aplicativo.

O Scapy utiliza Raw Sockets. Isso permite que ele ignore o processamento padrão do Kernel e pegue o pacote "cru".
- **Modo Promíscuo**: O Scapy coloca a placa de rede em um estado onde ela não descarta nada, mesmo pacotes que não são para aquele computador.
- **Cópia de Fluxo**: O pacote continua indo para o destino original, mas o Scapy faz uma cópia binária exata para análise.

No Scapy, um pacote não é uma string de texto, mas um objeto composto por fatias.

A estrutura visual que o Scapy usa é:
Ether() / IP() / TCP() / Raw()
- Ether(): Camada 2 (Endereços MAC).
- IP(): Camada 3 (Endereços IP, TTL, etc).
- TCP() / UDP(): Camada 4 (Portas, Flags, Sequência).
- Raw(): Onde os dados reais (payload) residem.

#### Usando o CMD do Scapy

No seu roteador, basta digitar scapy no terminal.
Isso abre um shell Python onde você pode interagir com pacotes em tempo real:

Comandos básicos para ensinar:

1. **ls()**: Lista todos os protocolos suportados (são centenas!).
2. **ls(IP)**: Mostra todos os campos que existem dentro da camada IP.
3. **p = IP(dst="10.0.1.2")/TCP(dport=80)**: Cria um pacote manualmente (Forge).
4. **p.show()**: Mostra a estrutura detalhada e "mastigada" do pacote.

Vamos agora criar um sniffer que tenta capturar um pacote de um serviço rodando no ambiente. Para isso você precisa iniciar o ambiente do aluno do [laboratório 2]().

Execute o seguinte sequência de comandos:
```bash
./lab.sh
```

em outro terminal execute:
```bash
docker exec -it client python3 client.py
```

Agora o padrão de tráfego será iniciado e podemos capturar os pacotes que transitam pela rede.

---

Digite o comando abaixo. Ele coloca o Scapy em modo de espera escutando a porta 23:

```python
pacote_unico = sniff(filter="tcp port 23", count=1)
```
O filter utiliza a sintaxe BPF para ignorar ruídos e focar apenas no Telnet (porta 23). O count=1 garante que o Scapy pare a execução assim que capturar exatamente um pacote, devolvendo o controle para o terminal

Parâmetros: O filter utiliza a sintaxe BPF para ignorar ruídos e focar apenas no Telnet (porta 23). O count=1 garante que o Scapy pare a execução assim que capturar exatamente um pacote, devolvendo o controle para o terminal.

O Scapy não retorna o pacote diretamente, mas sim um objeto do tipo PacketList.
``` python
> pacote
<Sniffed: TCP:1 UDP:0 ICMP:0 Other:0>
```
Ele contém todos os pacotes capturados. Note que ele já identifica automaticamente que o pacote capturado pertence ao protocolo TCP.

Você pode ver uma representação simplificada da "pilha" de protocolos com o seguinte comando.
```python
>>> pacote.summary()
Ether / IP / TCP 10.0.2.2:43688 > 10.0.1.2:telnet PA / Raw
```
Aqui vemos a hierarquia de encapsulamento: Ethernet → IP → TCP. O Scapy identifica o IP de origem, a porta efêmera do cliente (43688), o destino e as flags TCP (PA significa Push e Ack, indicando que há dados sendo enviados).

Como o sniff retorna uma lista, extraímos o primeiro item (índice 0) para a variável p.
```python
>>> p = pacote[0]
>>> p.summary()
'Ether / IP / TCP 10.0.2.2:43688 > 10.0.1.2:telnet PA / Raw'
```
Agora p é um objeto do tipo Packet. A partir daqui, podemos acessar qualquer campo interno individualmente
O comando abaixo, "abre a Matrioska" e mostra cada cabeçalho detalhadamente

```python
>>> p.show()
###[ Ethernet ]###
  dst       = 96:fb:d9:0d:38:9a
  src       = 42:8e:82:48:6a:49
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 59
     id        = 51770
     flags     = DF
     frag      = 0
     ttl       = 63
     proto     = tcp
     chksum    = 0x5a7f
     src       = 10.0.2.2
     dst       = 10.0.1.2
     \options   \
###[ TCP ]###
        sport     = 43688
        dport     = telnet
        seq       = 229584799
        ack       = 2316061442
        dataofs   = 8
        reserved  = 0
        flags     = PA
        window    = 63
        chksum    = 0x1731
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (2571162487, 570987929))]
###[ Raw ]###
           load      = b'lab123\n'
```

Como podemos observar [ Raw ]: A Camada de Aplicação (Conteúdo). Percebemos que load: Onde o a vulnerabilidade acontece. No Telnet, por não haver criptografia, a senha lab123\n aparece em texto puro, pronta para ser lida por qualquer um no meio do caminho.

Podemos também utilizar o scapy diretamento no python

```python
from scapy.all import sniff, IP, TCP

def analisar_pacote(pacote):
    if pacote.haslayer(IP):
        ip_origem = pacote[IP].src
        ip_destino = pactoe[IP].dst
        
        if pacote.haslayer(TCP):
            porta_origem = pacote[TCP].sport
            porta_destino = pacote[TCP].dport

        print(f"[TCP] {ip_origem}:{porta_origem} ---> {ip_destino}:{porta_destino}")

print("Iniciando o Sniffer do Roteador...")
print("Pressione Ctrl+C para interromper.\n")

# prn=analisar_pacote: Diz ao sniff para jogar cada pacote dentro da nossa função.
# store=0: Extremamente importante! Diz ao Scapy para NÃO guardar os pacotes na RAM, 
# caso contrário seu roteador travaria por falta de memória em poucos minutos.
sniff(prn=analisar_pacote, store=0)
```

Esse script, é basicamente o tcpdump.

### Entrega:
O laboratório consiste na construção de um sniffer utilizando Scapy. Utilize o ambiente disponibilizado e no script do roteador, construa um sistema que captura os pacotes e realize algumas métricas.

[Siga o modelo do relatório disponibilizado](https://docs.google.com/document/d/1WUkYRbJEfZo8q2HLxyIFxwmy1GCUEO4H9Xyezi9-AY4/edit?usp=sharing)