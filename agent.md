# Guia do Agente

# NOTA IMPORTANTE: EVITE APAGAR OU EDITAR O QUE TEMOS NO PROJETO ORIGINAL. 
## Fonte principal

Leia primeiro [`contexto.md`](/Users/eduardosrbl/Downloads/lab02/contexto.md). Esse arquivo é a fonte de verdade do trabalho e contém:

- objetivo do laboratório;
- topologia;
- restrições;
- atualizações do Classroom;
- comportamento esperado do roteador;
- cenários de teste;
- requisitos do relatório.

## Objetivo operacional

Implementar a defesa do laboratório no roteador, com foco em detectar tráfego malicioso por conteúdo de payload e impedir seu encaminhamento, preservando o tráfego legítimo.

## Regras obrigatórias

1. A entrega final deve concentrar a solução em `./roteador/router.py`.
2. A defesa não pode depender de IP ou porta como critério principal.
3. O critério principal de detecção deve ser o payload, uma assinatura ou padrão de conteúdo.
4. O modelo correto de drop é não encaminhar o pacote malicioso.
5. O tráfego legítimo deve continuar funcionando.
6. Os nomes dos arquivos e a árvore de diretórios do projeto devem ser mantidos.
7. O roteador deve seguir a base mais recente corrigida, conforme descrito em `contexto.md`.

## O que o agente deve fazer

1. Ler `contexto.md` por completo antes de decidir qualquer implementação.
2. Inspecionar `./roteador/router.py` para entender o fluxo atual de encaminhamento.
3. Identificar no código base o ponto certo para inserir a lógica de inspeção.
4. Inspecionar o ambiente local, inclusive o comportamento do atacante, para descobrir a assinatura real do tráfego malicioso, se ela não estiver explícita.
5. Implementar a detecção por payload e a decisão de encaminhar ou descartar.
6. Adicionar logs úteis para depuração e validação.
7. Validar que o tráfego legítimo continua passando e que o malicioso deixa de ser encaminhado.

## Checklist mínimo de validação

- cliente acessando serviços legítimos sem atacante;
- atacante ativo;
- tráfego legítimo e malicioso coexistindo;
- verificação de que o tráfego legítimo segue funcionando;
- verificação de que o tráfego malicioso é descartado.

## Restrições de interpretação

- não simplificar o problema para bloqueio por IP ou porta;
- não ignorar as atualizações do Classroom resumidas em `contexto.md`;
- não assumir que sniffing passivo por si só resolve o drop;
- não espalhar dependências da solução final por outros arquivos.

## Entrega esperada

Ao final, a implementação deve estar coerente com `contexto.md`, funcionar no modelo de encaminhamento manual do roteador e ser fácil de explicar no relatório.
