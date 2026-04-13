  
**Relatório de desenvolvimento das atividades**

*Instituto de Computação \- Universidade Estadual de Campinas*

*Allan M. de Souza, Rafael O. Jarczewski*

**Nome:** José Eduardo Santos
**RA:**  260551
**Ferramentas e bibliotecas utilizadas:** 
**Arquivos alterados:**

## **Análise Estatística do Tráfego (Sniffer)**

Descreva brevemente como o sniffer foi construído. Quais funções do Scapy foram fundamentais (ex: `sniff()`, `wrpcap()`) e como você estruturou o loop de captura para não perder pacotes em alta vazão.

O foco é a caracterização do tráfego coletado sob condições normais de uso.

1) Filtros e Captura  
   1) Filtros BPF (Berkeley Packet Filter) utilizados:  
   2) **Justificativa:** Por que esses filtros foram escolhidos para a análise?  
2) Vazão por Serviço (BPS)  
   1) Gráfico  
   2) Análise Descritiva  
3) Frequência de Pacotes.  
   1) Gráfico  
   2) Análise Descritiva  
4) Volume de pacotes pelo volume de bytes  
   1) Gráfico de dispersão (Scatter plot).  
   2) Análise descritiva

## **Detecção de Anomalias e Processamento de Firewall**

Nesta etapa, o sniffer atua como um elemento de rede (roteador/firewall) que decide o destino do pacote com base no seu comportamento.

**2.1 Comparativo Visual: Fluxo Normal vs. Anômalo**  
Apresenta a comparação lado a lado de como as métricas se comportam quando um ataque  é injetado.

**2.2 Método de Detecção Implementado**

Descreva a lógica utilizada para identificar o tráfego inválido.

* Critério de Decisão: Você não pode utilizar IP ou Porta de destino e origem para isso  
* Fluxo de Execução:  
  1. O pacote é capturado pela camada de processamento.  
  2. O método verifica os atributos em relação à lista negra ou limiares (thresholds).  
  3. Encaminhamento: Se normal, o pacote segue para `send()`.  
  4. Drop: Se anômalo, a função retorna um log de alerta e descarta o pacote (não executa o `send`).

**2.3 Eficácia do Firewall**

* Resultado: O método foi capaz de mitigar a anomalia?  
* Conclusão: Discorra sobre como o processamento no "roteador virtual" impactou a latência da rede e a segurança do host final.

