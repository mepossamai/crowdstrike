# Falcon NG-SIEM — Coletânea de Queries

Coletânea de consultas em **Falcon LogScale Query Language (LQL/CQL)** para investigação de hosts no **CrowdStrike Falcon Next-Gen SIEM**.

> **Como usar:** todas as queries usam o host `HOST_NAME` como exemplo. Substitua por `<HOSTNAME>` ou pelo `aid` do host alvo. O fuso horário das projeções está em `America/Sao_Paulo` — ajuste se necessário.

---

## Índice

1. [DNS — Domínios resolvidos por um host](#1-dns--domínios-resolvidos-por-um-host)
2. [DNS — Cada acesso individual com horário](#2-dns--cada-acesso-individual-com-horário)
3. [DNS — Agrupado por domínio com primeiro/último acesso](#3-dns--agrupado-por-domínio-com-primeiroúltimo-acesso)
4. [Conexões de rede — Listagem completa](#4-conexões-de-rede--listagem-completa)
5. [Conexões de rede — Resumo agrupado por destino](#5-conexões-de-rede--resumo-agrupado-por-destino)
6. [Conexões de rede — Apenas saída (outbound)](#6-conexões-de-rede--apenas-saída-outbound)
7. [Conexões enriquecidas com domínio DNS](#7-conexões-enriquecidas-com-domínio-dns)
8. [Visão "tipo firewall" — entrada, saída e escuta](#8-visão-tipo-firewall--entrada-saída-e-escuta)
9. [Portas em escuta no host](#9-portas-em-escuta-no-host)
10. [Conexões de entrada aceitas](#10-conexões-de-entrada-aceitas)
11. [Timeline completa de rede](#11-timeline-completa-de-rede)
12. [Conexões enriquecidas com processo de origem](#12-conexões-enriquecidas-com-processo-de-origem)
13. [Top processos por volume de rede](#13-top-processos-por-volume-de-rede)
14. [Boot e shutdown — eventos explícitos](#14-boot-e-shutdown--eventos-explícitos)
15. [Boot derivado do MachineBootTime](#15-boot-derivado-do-machineboottime)
16. [Primeira e última atividade por dia](#16-primeira-e-última-atividade-por-dia)
17. [Detectar reboots por lacunas na telemetria](#17-detectar-reboots-por-lacunas-na-telemetria)

---

## 1. DNS — Domínios resolvidos por um host

Lista todos os domínios consultados pelo host, com contagem de acessos e horários do primeiro e último acesso. Visão agregada e ordenada pelos mais frequentes.

```
#event_simpleName=DnsRequest
| ComputerName="HOST_NAME"
| groupBy([DomainName], function=[count(), min(@timestamp, as=primeiro), max(@timestamp, as=ultimo)])
| sort(_count, order=desc)
```

---

## 2. DNS — Cada acesso individual com horário

Lista cada requisição DNS individualmente, com horário formatado em BRT, ordenada cronologicamente. Útil para reconstruir a sequência exata de eventos.

```
#event_simpleName=DnsRequest
| ComputerName="HOST_NAME"
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, ComputerName, DomainName, RequestType])
| sort(horario_brt, order=asc)
```

---

## 3. DNS — Agrupado por domínio com primeiro/último acesso

Mostra cada domínio uma única vez, com quantas vezes foi acessado e horários (BRT) do primeiro e último acesso. Ordenado pelo acesso mais recente.

```
#event_simpleName=DnsRequest
| ComputerName="HOST_NAME"
| groupBy([DomainName], function=[count(as=acessos), min(@timestamp, as=primeiro_acesso), max(@timestamp, as=ultimo_acesso)])
| formatTime("%Y-%m-%d %H:%M:%S", field=primeiro_acesso, timezone="America/Sao_Paulo", as=primeiro_brt)
| formatTime("%Y-%m-%d %H:%M:%S", field=ultimo_acesso, timezone="America/Sao_Paulo", as=ultimo_brt)
| table([DomainName, acessos, primeiro_brt, ultimo_brt])
| sort(ultimo_acesso, order=desc)
```

---

## 4. Conexões de rede — Listagem completa

Lista todas as conexões de rede (IPv4 e IPv6) do host, mostrando IP/porta de destino, protocolo, direção e binário responsável.

```
#event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, ComputerName, RemoteAddressIP4, RemoteAddressIP6, RemotePort, Protocol, ConnectionDirection, ImageFileName])
| sort(horario_brt, order=asc)
```

**Legenda dos campos:**
- `Protocol`: `6` = TCP, `17` = UDP, `1` = ICMP
- `ConnectionDirection`: `0` = saída (outbound), `1` = entrada (inbound)

---

## 5. Conexões de rede — Resumo agrupado por destino

Visão consolidada de quantas vezes cada combinação IP+porta+processo conectou, com primeiro e último horário. Útil para identificar destinos mais acessados.

```
#event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| coalesce([RemoteAddressIP4, RemoteAddressIP6], as=RemoteIP)
| groupBy([RemoteIP, RemotePort, ImageFileName], function=[count(as=conexoes), min(@timestamp, as=primeiro), max(@timestamp, as=ultimo)])
| formatTime("%Y-%m-%d %H:%M:%S", field=primeiro, timezone="America/Sao_Paulo", as=primeiro_brt)
| formatTime("%Y-%m-%d %H:%M:%S", field=ultimo, timezone="America/Sao_Paulo", as=ultimo_brt)
| table([RemoteIP, RemotePort, ImageFileName, conexoes, primeiro_brt, ultimo_brt])
| sort(ultimo, order=desc)
```

---

## 6. Conexões de rede — Apenas saída (outbound)

Filtra apenas conexões iniciadas pelo host (saída). Geralmente o que importa em investigação de exfiltração ou C2.

```
#event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| ConnectionDirection=0
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, RemoteAddressIP4, RemotePort, Protocol, ImageFileName])
| sort(horario_brt, order=asc)
```

---

## 7. Conexões enriquecidas com domínio DNS

Lista conexões de rede e enriquece cada IP com o domínio que foi resolvido para ele (quando há resolução DNS na janela). Conexões sem DNS associado aparecem com `DomainName = "-"`.

```
defineTable(
  name="dns_lookup",
  query={
    #event_simpleName=DnsRequest
    | ComputerName="HOST_NAME"
    | IP4Records=*
    | splitString(field=IP4Records, by=";", as=RemoteIP)
    | RemoteIP=~replace(regex="\\s+", with="")
    | groupBy([RemoteIP], function=collect([DomainName], separator=", "))
  },
  include=[RemoteIP, DomainName]
)
| #event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| coalesce([RemoteAddressIP4, RemoteAddressIP6], as=RemoteIP)
| match(table="dns_lookup", field=RemoteIP, strict=false)
| default(field=DomainName, value="-")
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, RemoteIP, RemotePort, Protocol, ConnectionDirection, ImageFileName, DomainName])
| sort(horario_brt, order=asc)
```

---

## 8. Visão "tipo firewall" — entrada, saída e escuta

Reproduz uma visão equivalente a log de firewall sem precisar do módulo Falcon Firewall Management. Combina conexões de saída, entrada aceita e portas em escuta numa única projeção, com direção e protocolo legíveis.

```
#event_simpleName=/^NetworkConnectIP(4|6)$|^NetworkListenIP(4|6)$|^NetworkReceiveAcceptIP(4|6)$/
| ComputerName="HOST_NAME"
| coalesce([RemoteAddressIP4, RemoteAddressIP6], as=RemoteIP)
| coalesce([LocalAddressIP4, LocalAddressIP6], as=LocalIP)
| case {
    ConnectionDirection=0 | Direcao := "OUTBOUND";
    ConnectionDirection=1 | Direcao := "INBOUND";
    * | Direcao := "OTHER"
  }
| case {
    Protocol=6  | Proto := "TCP";
    Protocol=17 | Proto := "UDP";
    Protocol=1  | Proto := "ICMP";
    * | Proto := Protocol
  }
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, #event_simpleName, Direcao, Proto, LocalIP, LocalPort, RemoteIP, RemotePort, ImageFileName])
| sort(horario_brt, order=asc)
```

---

## 9. Portas em escuta no host

Equivalente ao `netstat -an | findstr LISTEN` — mostra quais portas o host está expondo e qual processo está escutando.

```
#event_simpleName=/^NetworkListenIP(4|6)$/
| ComputerName="HOST_NAME"
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, LocalAddressIP4, LocalPort, Protocol, ImageFileName])
| sort(horario_brt, order=asc)
```

---

## 10. Conexões de entrada aceitas

Lista todas as conexões que chegaram ao host e foram aceitas (inbound efetivo).

```
#event_simpleName=/^NetworkReceiveAcceptIP(4|6)$/
| ComputerName="HOST_NAME"
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, RemoteAddressIP4, RemotePort, LocalAddressIP4, LocalPort, ImageFileName])
| sort(horario_brt, order=asc)
```

---

## 11. Timeline completa de rede

Junta DNS, conexões de saída, conexões aceitas e portas em escuta numa única timeline cronológica, com enriquecimento de domínio. Visão consolidada de toda atividade de rede do host.

```
defineTable(
  name="dns_lookup",
  query={
    #event_simpleName=DnsRequest
    | ComputerName="HOST_NAME"
    | IP4Records=*
    | splitString(field=IP4Records, by=";", as=RemoteIP)
    | RemoteIP=~replace(regex="\\s+", with="")
    | groupBy([RemoteIP], function=collect([DomainName], separator=", "))
  },
  include=[RemoteIP, DomainName]
)
| #event_simpleName=/^(DnsRequest|NetworkConnectIP4|NetworkConnectIP6|NetworkListenIP4|NetworkListenIP6|NetworkReceiveAcceptIP4|NetworkReceiveAcceptIP6)$/
| ComputerName="HOST_NAME"
| coalesce([RemoteAddressIP4, RemoteAddressIP6], as=RemoteIP)
| coalesce([LocalAddressIP4, LocalAddressIP6], as=LocalIP)
| match(table="dns_lookup", field=RemoteIP, strict=false)
| case {
    #event_simpleName=DnsRequest                | Tipo := "DNS_QUERY";
    #event_simpleName=/NetworkConnectIP/        | Tipo := "OUTBOUND";
    #event_simpleName=/NetworkListenIP/         | Tipo := "LISTEN";
    #event_simpleName=/NetworkReceiveAcceptIP/  | Tipo := "INBOUND";
  }
| case {
    Protocol=6  | Proto := "TCP";
    Protocol=17 | Proto := "UDP";
    Protocol=1  | Proto := "ICMP";
    * | Proto := "-"
  }
| default(field=DomainName, value="-")
| default(field=RemotePort, value="-")
| default(field=LocalPort,  value="-")
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, Tipo, Proto, LocalIP, LocalPort, RemoteIP, RemotePort, DomainName, ImageFileName])
| sort(horario_brt, order=asc)
```

**Filtros úteis para acrescentar:**
- Excluir RFC1918: `| RemoteIP!=/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/`
- Excluir loopback: `| RemoteIP!=/^127\./ | RemoteIP!="::1"`
- Apenas porta 443: `| RemotePort=443`
- Apenas um processo: `| ImageFileName=/chrome\.exe$/i`

---

## 12. Conexões enriquecidas com processo de origem

Correlaciona cada conexão de rede com o `ProcessRollup2` correspondente para trazer linha de comando completa, usuário, processo pai e binário. Essencial para investigação aprofundada.

```
defineTable(
  name="proc_lookup",
  query={
    #event_simpleName=ProcessRollup2
    | ComputerName="HOST_NAME"
    | groupBy([TargetProcessId],
              function=[selectLast([ImageFileName, CommandLine, UserName, ParentBaseFileName, ParentProcessId])])
    | rename(field=TargetProcessId, as=ContextProcessId)
  },
  include=[ContextProcessId, ImageFileName, CommandLine, UserName, ParentBaseFileName, ParentProcessId]
)
| defineTable(
    name="dns_lookup",
    query={
      #event_simpleName=DnsRequest
      | ComputerName="HOST_NAME"
      | IP4Records=*
      | splitString(field=IP4Records, by=";", as=RemoteIP)
      | RemoteIP=~replace(regex="\\s+", with="")
      | groupBy([RemoteIP], function=collect([DomainName], separator=", "))
    },
    include=[RemoteIP, DomainName]
  )
| #event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| coalesce([RemoteAddressIP4, RemoteAddressIP6], as=RemoteIP)
| match(table="dns_lookup",  field=RemoteIP,         strict=false)
| match(table="proc_lookup", field=ContextProcessId, strict=false)
| default(field=DomainName,         value="-")
| default(field=CommandLine,        value="-")
| default(field=UserName,           value="-")
| default(field=ParentBaseFileName, value="-")
| case {
    Protocol=6  | Proto := "TCP";
    Protocol=17 | Proto := "UDP";
    Protocol=1  | Proto := "ICMP";
    * | Proto := "-"
  }
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, Proto, RemoteIP, RemotePort, DomainName, ImageFileName, UserName, ParentBaseFileName, CommandLine])
| sort(horario_brt, order=asc)
```

---

## 13. Top processos por volume de rede

Identifica quais processos mais conversaram com a rede no período: número de conexões, IPs únicos contatados e portas usadas.

```
defineTable(
  name="proc_lookup",
  query={
    #event_simpleName=ProcessRollup2
    | ComputerName="HOST_NAME"
    | groupBy([TargetProcessId], function=[selectLast([ImageFileName, CommandLine, UserName])])
    | rename(field=TargetProcessId, as=ContextProcessId)
  },
  include=[ContextProcessId, ImageFileName, CommandLine, UserName]
)
| #event_simpleName=/^NetworkConnectIP(4|6)$/
| ComputerName="HOST_NAME"
| match(table="proc_lookup", field=ContextProcessId, strict=false)
| groupBy([ImageFileName, UserName],
          function=[count(as=conexoes),
                    count(RemoteAddressIP4, distinct=true, as=ips_unicos),
                    collect([RemotePort], separator=",")])
| sort(conexoes, order=desc)
```

---

## 14. Boot e shutdown — eventos explícitos

Lista eventos do ciclo de vida do sistema: inicialização do sensor, info do SO no boot, timestamp de boot e shutdown ordenado.

```
#event_simpleName=/^(SuccessfulStartup|SystemShutdown|OsVersionInfo|MachineBootTime)$/
| ComputerName="HOST_NAME"
| case {
    #event_simpleName=SuccessfulStartup | Evento := "BOOT (sensor iniciou)";
    #event_simpleName=OsVersionInfo     | Evento := "BOOT (info do SO)";
    #event_simpleName=MachineBootTime   | Evento := "BOOT (timestamp)";
    #event_simpleName=SystemShutdown    | Evento := "SHUTDOWN";
  }
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=horario_brt)
| table([horario_brt, Evento, #event_simpleName])
| sort(horario_brt, order=asc)
```

---

## 15. Boot derivado do MachineBootTime

Quando disponível, o campo `MachineBootTime` traz o timestamp exato do último boot do SO. Esta query lista todos os boots únicos do período.

```
#event_simpleName=OsVersionInfo
| ComputerName="HOST_NAME"
| MachineBootTime=*
| BootTimeMs := MachineBootTime * 1000
| formatTime("%Y-%m-%d %H:%M:%S", field=BootTimeMs, timezone="America/Sao_Paulo", as=boot_brt)
| groupBy([boot_brt], function=count(as=ocorrencias))
| sort(boot_brt, order=asc)
```

---

## 16. Primeira e última atividade por dia

Aproxima "ligou de manhã / desligou à noite" mostrando o primeiro e o último evento de telemetria por dia.

```
#repo=base_sensor
| ComputerName="HOST_NAME"
| timeDay := formatTime("%Y-%m-%d", field=@timestamp, timezone="America/Sao_Paulo")
| groupBy([timeDay], function=[
    min(@timestamp, as=primeira_atividade),
    max(@timestamp, as=ultima_atividade),
    count(as=eventos_no_dia)
  ])
| formatTime("%H:%M:%S", field=primeira_atividade, timezone="America/Sao_Paulo", as=ligou_aprox)
| formatTime("%H:%M:%S", field=ultima_atividade,   timezone="America/Sao_Paulo", as=desligou_aprox)
| table([timeDay, ligou_aprox, desligou_aprox, eventos_no_dia])
| sort(timeDay, order=asc)
```

---

## 17. Detectar reboots por lacunas na telemetria

Detecta cada vez que o host voltou a enviar eventos após mais de 10 minutos de silêncio — indicando boot, retorno de suspensão ou retomada de rede.

```
#repo=base_sensor
| ComputerName="HOST_NAME"
| sort(@timestamp, order=asc)
| diff_min := (@timestamp - lag(@timestamp)) / 60000
| diff_min > 10
| formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/Sao_Paulo", as=retomada_brt)
| table([retomada_brt, diff_min])
| sort(retomada_brt, order=asc)
```

---

## Notas gerais

### Eventos do sensor mais usados nesta coletânea

| Evento | Descrição |
|---|---|
| `DnsRequest` | Resolução DNS feita pelo host |
| `NetworkConnectIP4` / `NetworkConnectIP6` | Conexão de rede iniciada |
| `NetworkListenIP4` / `NetworkListenIP6` | Porta aberta para escuta |
| `NetworkReceiveAcceptIP4` / `NetworkReceiveAcceptIP6` | Conexão de entrada aceita |
| `ProcessRollup2` | Metadados completos de processo |
| `OsVersionInfo` | Informações do SO (inclui boot time) |
| `SuccessfulStartup` | Sensor iniciou com sucesso |
| `SystemShutdown` | Desligamento ordenado |

### Boas práticas

- Prefira filtrar por **`aid`** em vez de `ComputerName` quando o histórico for longo — nomes podem mudar.
- Sempre defina uma **janela de tempo** explícita no console; queries amplas podem estourar limites.
- Use **`strict=false`** em `match()` para preservar registros sem correspondência (equivalente a left join).
- O `ProcessRollup2` é emitido várias vezes por processo (start/stop) — use `selectLast` para pegar a versão mais completa.
- O `IP4Records` do `DnsRequest` vem como string com IPs separados por `;` (ponto-e-vírgula) — use `splitString`, não `split`.

### Limitações conhecidas

- O sensor aplica **filtros internos de redução de ruído** — nem toda conexão local/repetitiva é reportada.
- **Cache DNS do SO** faz muitas conexões aparecerem sem `DomainName`.
- **DoH/DoT** mascara DNS — o sensor só vê a conexão TCP/443 para o resolver.
- Para visão completa em tempo real, é necessário ter **Enhanced Visibility** habilitada na política.

---