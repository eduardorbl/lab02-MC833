# Laboratório 2 — Contexto Consolidado

## 1. Objetivo do laboratório

O laboratório simula um ambiente de rede controlado com tráfego legítimo e tráfego malicioso para praticar:

- análise de pacotes em tempo real;
- entendimento prático da pilha TCP/IP;
- uso da biblioteca Scapy para inspeção de tráfego;
- implementação de um mecanismo de detecção de tráfego malicioso;
- implementação de um mecanismo de bloqueio ou descarte de pacotes maliciosos no roteador.

O ponto central do trabalho é implementar a defesa no roteador, e não no cliente, no servidor ou no atacante.

## 2. Cenário da rede

O ambiente possui quatro nós principais:

### Cliente

Gera tráfego legítimo para os serviços expostos pelo servidor.

### Servidor

Hospeda os serviços:

- Telnet na porta `23`;
- HTTP/Nginx na porta `80`;
- MariaDB na porta `3306`.

### Agente malicioso

Injeta tráfego de ataque na rede. O comportamento relevante do atacante é:

- uso de IP Spoofing, alterando constantemente o endereço IP de origem;
- uso de Port Hopping, com portas aleatórias ou dinâmicas.

Por isso, a defesa não pode depender apenas de bloquear IP ou porta fixa.

### Roteador

É o ponto central da topologia e o local onde a defesa deve ser implementada. O script no roteador deve observar os pacotes que passam por ele e decidir o que será encaminhado.

## 3. O que o aluno precisa implementar

No roteador, em Python com Scapy, a solução deve:

1. capturar e analisar pacotes em tempo real;
2. inspecionar o payload dos pacotes;
3. identificar tráfego malicioso por assinatura, padrão de conteúdo ou comportamento visível no payload;
4. alertar o administrador e/ou bloquear o tráfego malicioso;
5. fazer isso sem usar IP ou porta como critério principal.

Em outras palavras, a lógica esperada é uma defesa baseada no conteúdo do pacote e no comportamento observável no payload, não em origem ou destino fixo.

## 4. Ideia central da detecção

O enunciado destaca que o atacante envia uma assinatura no payload, como por exemplo:

- uma string específica;
- um comando específico;
- uma sequência suspeita de bytes ou texto;
- um padrão que caracterize varredura, exploração ou comando malicioso.

O núcleo da solução é:

1. capturar pacotes;
2. verificar se têm camadas relevantes;
3. extrair o payload;
4. procurar a assinatura maliciosa;
5. encaminhar apenas o tráfego legítimo;
6. registrar alerta quando houver detecção.

## 5. O que o laboratório quer avaliar

### Entendimento da pilha TCP/IP

É necessário entender que:

- pacotes têm camadas;
- nem todo pacote possui payload útil para análise;
- é preciso distinguir camadas IP, TCP e payload bruto;
- o roteador está no fluxo de encaminhamento.

### Uso prático de Scapy

Espera-se uso de Scapy para:

- captura;
- leitura de camadas;
- extração de conteúdo;
- inspeção de tráfego em tempo real.

### Implementação de defesa

Não basta observar. O laboratório explicitamente cobra:

- detecção de anomalias;
- descarte de pacotes com tráfego malicioso.

## 6. Topologia e fluxo esperado

### Fluxo legítimo

O cliente deve continuar acessando normalmente o servidor, inclusive nos serviços:

- HTTP na porta `80`;
- Telnet na porta `23`;
- MariaDB na porta `3306`.

### Fluxo malicioso

O badguy envia pacotes potencialmente maliciosos alterando:

- IP de origem;
- portas de origem;
- possivelmente o padrão superficial de envio.

A defesa deve reconhecer o ataque pelo conteúdo, e não pela identidade estática do emissor.

### Papel do roteador

Como está no meio do caminho, o roteador é o ponto adequado para:

- observar o tráfego;
- decidir o que será encaminhado;
- impedir que o tráfego malicioso chegue ao servidor.

## 7. Estrutura do ambiente

O laboratório é fornecido via Docker. Os containers principais são:

- `client`;
- `roteador`;
- `servidor`;
- `badguy`.

Arquivos mapeados diretamente para os containers:

- `client.py`;
- `server.py`;
- `router.py`;
- `attacker_tcpscan.sh`.

Regra importante:

- os nomes dos arquivos devem ser mantidos;
- a árvore de diretórios deve ser mantida.

## 8. Restrição principal de entrega

O enunciado é explícito:

> Faça as alterações apenas no arquivo `./roteador/router.py`

Consequência prática:

- a entrega final deve concentrar a solução em `./roteador/router.py`;
- mudanças em `client.py`, `server.py` ou `attacker_tcpscan.sh` não devem ser necessárias para a solução final;
- se esses outros arquivos forem alterados para testes pessoais, isso não deve virar dependência da entrega.

## 9. Como executar o ambiente

### Subir o laboratório

```bash
./lab.sh
```

### Copiar alterações locais para os containers

```bash
./copy-files.sh
```

Se esse passo for esquecido, o container pode continuar executando a versão antiga do arquivo.

### Iniciar o cliente

```bash
docker exec -it client python3 client.py
```

### Iniciar o atacante

```bash
docker exec -it badguy bash ./attacker_tcpscan.sh
```

### Observar o tráfego

O enunciado informa que o tráfego no servidor pode ser inspecionado com alguma ferramenta de sniffer mostrada em aula. Isso serve para validar:

- se os pacotes legítimos estão chegando;
- se o ataque está chegando ou sendo bloqueado;
- o comportamento antes e depois da defesa.

## 10. Atualizações importantes do Classroom

Essas atualizações alteram a interpretação prática da implementação.

### Atualização 1

Foi informado que o `.zip` do trabalho foi atualizado e que:

- houve mudança relacionada a `ip_forward=0`;
- foi adicionado um código base de encaminhamento de pacotes no roteador;
- esse código indica onde a lógica do aluno deve ser inserida;
- a alteração foi feita porque o Scapy cria cópias dos pacotes e, na abordagem anterior, seriam necessárias outras ferramentas para dropar pacotes.

### Interpretação correta da atualização 1

O roteador passou a ser pensado no modelo:

1. receber o pacote;
2. analisar o pacote;
3. decidir se ele deve ser reenviado;
4. encaminhar apenas se for legítimo;
5. não encaminhar se for malicioso.

Isso significa que, no contexto atualizado do trabalho, o drop deve ser entendido como não encaminhar o pacote.

### Atualização 2

Depois, o monitor informou que houve outra alteração no arquivo do roteador, porque a versão anterior não estava encaminhando todos os pacotes. A orientação foi usar a nova versão, descrita como mais simples.

### Consequência prática das atualizações

- é essencial usar a versão mais nova do `router.py` disponibilizada no Classroom;
- implementar sobre a base antiga pode introduzir falhas de encaminhamento que não têm relação com a lógica da defesa;
- o código base novo do roteador deve ser aproveitado.

## 11. Interpretação técnica correta sobre o drop

Pelas notas do Classroom:

- Scapy, em sniffing comum, observa pacotes e normalmente trabalha sobre cópias;
- isso não equivale a bloquear diretamente o pacote original em trânsito;
- por isso o laboratório foi ajustado para um roteador com encaminhamento controlado manualmente.

Assim, a lógica correta é:

- se o pacote for legítimo, o script o encaminha;
- se o pacote for malicioso, o script não o encaminha.

## 12. Comportamento esperado do `router.py`

O `router.py` deve seguir a lógica abaixo:

1. capturar os pacotes que chegam ao roteador;
2. identificar quais são relevantes para encaminhamento;
3. analisar o conteúdo do payload;
4. comparar com a assinatura do ataque;
5. se o pacote for legítimo, encaminhar;
6. se o pacote for malicioso, não encaminhar;
7. registrar log ou alerta do evento.

## 13. O que a solução deve preservar

### Tráfego legítimo

O roteador não pode simplesmente matar todo o tráfego. A comunicação normal entre cliente e servidor precisa continuar funcionando.

### Critério principal de detecção

IP e porta podem aparecer apenas como apoio para logs, mas não devem ser o critério principal de decisão, porque o atacante altera esses campos.

### Base da classificação

O critério principal deve ser o conteúdo do payload ou a assinatura maliciosa visível no pacote.

## 14. O que não deve ser feito

- não transformar a proposta em um firewall baseado apenas em IP ou porta;
- não ignorar as atualizações do Classroom;
- não implementar a solução final espalhando dependências por arquivos além de `./roteador/router.py`;
- não esquecer de rodar `./copy-files.sh`;
- não usar a versão antiga do roteador;
- não validar apenas um cenário de teste.

## 15. Fluxo recomendado de desenvolvimento

### Etapa 1. Validar o ambiente

- subir o ambiente com `./lab.sh`;
- garantir que os containers estão rodando;
- executar cliente e atacante;
- observar o comportamento atual.

### Etapa 2. Confirmar a base correta do roteador

- verificar que o `router.py` usado é a versão corrigida mais recente;
- localizar o ponto indicado no código base para inserir a lógica da defesa.

### Etapa 3. Implementar a inspeção do payload

- identificar as camadas relevantes;
- extrair o payload;
- procurar a assinatura maliciosa.

### Etapa 4. Implementar a decisão de encaminhar ou descartar

- tráfego legítimo deve seguir;
- tráfego malicioso não deve ser encaminhado.

### Etapa 5. Adicionar logs

É útil registrar:

- origem e destino observados;
- serviço ou porta, se isso ajudar na análise;
- motivo da classificação;
- decisão final de encaminhamento ou drop.

### Etapa 6. Repetir testes

Após cada alteração:

```bash
./copy-files.sh
```

e então repetir os testes.

## 16. Cenários mínimos de teste

Validar pelo menos:

- tráfego legítimo sem atacante;
- tráfego com atacante;
- tráfego legítimo coexistindo com atacante;
- se o tráfego legítimo continua passando;
- se o tráfego malicioso deixa de chegar ao servidor.

## 17. Pontos que devem aparecer no relatório

O enunciado diz explicitamente para seguir o modelo de relatório disponibilizado. O relatório deve cobrir, de forma clara:

1. objetivo do laboratório;
2. topologia da rede;
3. serviços expostos no servidor;
4. estratégia do atacante, incluindo IP Spoofing e Port Hopping;
5. estratégia da defesa;
6. uso de payload ou assinatura como critério principal;
7. impacto das atualizações do Classroom;
8. metodologia de testes;
9. resultados obtidos;
10. limitações, se houver;
11. uso de IA, conforme exigido no enunciado.

## 18. Prazo e regras

- entrega via Classroom até `14/04/2026 às 23:59`;
- a atividade é individual;
- o uso de IA deve ser informado, justificado e detalhado, incluindo em quais partes foi utilizado;
- qualquer forma de cópia ou plágio pode resultar em nota zero.

## 19. Descrição organizada do diagrama do professor

### Composição visual

A imagem representa a topologia simplificada da rede do laboratório. Ela tem:

- fundo preto;
- quatro blocos retangulares brancos com cantos arredondados, representando os nós principais;
- um bloco menor à direita, associado aos serviços do servidor.

Disposição espacial:

- parte superior esquerda: Cliente;
- parte superior central: Roteador;
- parte superior direita: Servidor;
- parte inferior esquerda: Agente Malicioso;
- à direita e abaixo do servidor: quadro de Serviços.

Mesmo sem enlaces explícitos, a composição sugere claramente o fluxo lógico da rede.

### Interpretação dos elementos

#### Cliente

Representa a origem do tráfego legítimo. É o nó que acessa os serviços do servidor e cujo tráfego não deve ser bloqueado.

#### Roteador

É o ponto central da imagem e também da atividade. Sua posição indica que ele é o intermediário entre emissores de tráfego e o servidor. No laboratório, é nele que a defesa deve:

- capturar pacotes;
- inspecionar conteúdo;
- analisar payload;
- identificar assinaturas maliciosas;
- decidir por encaminhamento ou descarte.

#### Servidor

Representa o destino do tráfego legítimo e o alvo potencial do agente malicioso. A posição à direita do roteador reforça que o tráfego deve passar pelo ponto de inspeção antes de chegar nele.

#### Quadro de serviços

Lista os serviços hospedados pelo servidor:

1. `telnet`
2. `nginx`
3. `mariadb`

Esses serviços correspondem, no enunciado, às portas `23`, `80` e `3306`.

#### Agente Malicioso

Representa a fonte de tráfego hostil. Sua posição separada do cliente ajuda a mostrar que ele não faz parte do fluxo legítimo da aplicação, mas interfere no ambiente com tráfego malicioso.

### Fluxo lógico sugerido pelo diagrama

Fluxo legítimo:

```text
Cliente -> Roteador -> Servidor
```

Fluxo malicioso:

```text
Agente Malicioso -> rede / roteador / servidor
```

### Papel didático da imagem

A imagem não tenta mostrar detalhes de camada física, interfaces, cabos, sub-redes ou endereçamento IP. Ela funciona como um mapa conceitual para destacar:

- quem gera tráfego legítimo;
- quem gera tráfego malicioso;
- onde a defesa deve ser implementada;
- quem hospeda os serviços-alvo.

### Relação com o enunciado

O diagrama está alinhado ao texto do trabalho:

- mostra os quatro nós principais citados no enunciado;
- confirma os serviços Telnet, HTTP/Nginx e MariaDB;
- reforça o roteador como ponto de defesa e inspeção.

### Mensagem principal da imagem

A imagem comunica que existe uma rede pequena e controlada em que:

- um cliente legítimo acessa um servidor;
- um agente malicioso tenta atacar o ambiente;
- o roteador é o ponto ideal para observar o tráfego e aplicar a defesa.
