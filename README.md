# Ransomware Behavior Analyzer

Ferramenta para monitoramento de comportamento suspeito em sistemas Linux, com foco na identificação de atividades compatíveis com ransomware.

O projeto combina módulos em Python e C. O Python é utilizado para monitoramento, correlação de eventos e interface de terminal, enquanto o C é responsável por operações que exigem maior desempenho, como cálculo de entropia e leitura de informações do sistema.

## Estrutura

```
ransomware-analyzer/
├── entropy_calc.c
├── entropy_calc.so
├── c_bridge.py
├── config.py
├── logger.py
├── allowlist.py
├── proc_monitor.py
├── net_monitor.py
├── detector.py
├── monitor.py
├── main.py
├── run.sh
└── logs/
```

## Objetivo

Detectar possíveis processos de criptografia em massa por meio da análise de eventos do sistema de arquivos, características dos arquivos modificados, atividade de rede e informações obtidas pelo sistema `/proc`.

A detecção é baseada em comportamento observado e não em assinaturas específicas de malware.

## Funcionalidades

### Monitoramento de arquivos

Utiliza `inotify` através da biblioteca Watchdog para acompanhar alterações em diretórios monitorados.

Eventos observados:

* Criação de arquivos
* Modificação de arquivos
* Exclusão de arquivos
* Renomeação e movimentação

### Análise de entropia

O módulo em C calcula a entropia de arquivos modificados para identificar alterações compatíveis com processos de criptografia.

São coletadas:

* Entropia Shannon
* Distribuição de frequência dos bytes
* Amostras parciais do conteúdo para reduzir impacto de desempenho

### Monitoramento de processos

Obtém informações de processos por meio do sistema `/proc`.

Informações utilizadas:

* PID
* Nome do processo
* Executável associado
* Quantidade de descritores de arquivo
* Consumo de memória

Quando possível, eventos de arquivos são associados ao processo responsável.

### Monitoramento de conexões

Realiza leitura periódica de `/proc/net/tcp` para identificar conexões ativas.

O objetivo é detectar:

* Conexões externas incomuns
* Grande volume de conexões para um mesmo destino
* Comunicação com portas frequentemente associadas a malware

### Sistema de detecção

A correlação de eventos considera fatores como:

* Grande volume de escrita em curto período
* Renomeações em massa
* Exclusões em massa
* Arquivos com entropia elevada
* Criação de extensões incomuns
* Presença de extensões associadas a famílias conhecidas de ransomware
* Criação de arquivos com características de notas de resgate

Cada evento contribui para uma pontuação de risco acumulada.

### Lista de confiança

Processos legítimos podem ser cadastrados por hash SHA-256 para reduzir falsos positivos.

## Registro de eventos

Todos os eventos são armazenados em formato JSONL para posterior análise.

Exemplo:

```json
{
  "ts": "2025-01-15T14:32:01",
  "severity": "ALERT",
  "event": "HIGH_ENTROPY",
  "file": "/tmp/test/document.txt"
}
```

## Requisitos

* Linux
* Python 3.10+
* GCC
* watchdog
* psutil (opcional)

## Considerações

A ferramenta foi desenvolvida para fins educacionais e de pesquisa em segurança ofensiva e defensiva. O foco principal é a identificação de padrões comportamentais normalmente observados durante ataques de ransomware, permitindo análise e resposta em ambiente controlado.
