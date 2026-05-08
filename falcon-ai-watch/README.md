# falcon-ai-watch

> Track shadow AI coding tools usage across your endpoints with CrowdStrike Falcon NG-SIEM.

Dashboard para o **CrowdStrike Falcon Next-Gen SIEM** que monitora o uso de plataformas de **AI App Builders / Vibe Coding** dentro do parque corporativo, oferecendo visibilidade sobre Shadow IT relacionado a ferramentas de geração de código com IA.

---

## Sobre o projeto

Plataformas de geração de aplicações com IA (Lovable, Replit, v0, Bolt.new, Base44, Cursor, Windsurf, Codeium, Devin e similares) representam um vetor crescente de Shadow IT em ambientes corporativos. Os principais riscos associados incluem:

- Envio de código proprietário como contexto para LLMs externas
- Vazamento de credenciais e secrets em prompts
- Geração de dependências com vulnerabilidades não revisadas
- Criação de aplicações fora do pipeline corporativo de DevSecOps

Este dashboard fornece à equipe de Segurança da Informação visibilidade completa sobre quais hosts e usuários acessam essas plataformas, com filtro selecionável por plataforma e detalhamento por subdomínio, processo e usuário interativo logado.

---

## Plataformas monitoradas

| Plataforma | Domínio | Categoria |
|---|---|---|
| Lovable | `lovable.dev` / `lovable.app` | AI App Builder |
| Replit | `replit.com` | AI App Builder |
| v0 (Vercel) | `v0.dev` | AI App Builder |
| Bolt.new | `bolt.new` | AI App Builder |
| Base44 | `base44.com` | AI App Builder |
| Cursor | `cursor.com` / `cursor.sh` | AI Code Editor |
| Windsurf | `windsurf.com` | AI Code Editor |
| Codeium | `codeium.com` | AI Code Assistant |
| Devin | `devin.ai` | Autonomous AI Agent |
| Cognition Labs | `cognition.ai` | Autonomous AI Agent |

Novas plataformas podem ser adicionadas facilmente editando o parâmetro `dominios` do dashboard.

---

## Estrutura do dashboard

O dashboard contém 8 widgets organizados em 4 camadas visuais:

**Camada 1 — KPIs executivos (topo)**
- Total de Hosts Únicos Acessando
- Total de Subdomínios Distintos Acessados
- Total de Requisições DNS

**Camada 2 — Linha do tempo**
- Linha do Tempo de Acessos (hosts únicos por hora)

**Camada 3 — Rankings (lado a lado)**
- Top 20 - Subdomínios Acessados
- Top Hosts (Endpoints) que Mais Acessam
- Acessos por Usuário (ranking de usuários humanos por plataforma)

**Camada 4 — Detalhamento granular**
- Detalhamento Completo (domínio, usuário logado, host, processo, requisições e último acesso)

---

## Filtro interativo (parâmetro)

O dashboard possui um parâmetro do tipo **FixedList** chamado `Plataformas de IA`, que permite ao usuário selecionar qual plataforma quer analisar sem precisar editar nenhuma query. O valor padrão é `lovable.app`.

---

## Identificação de usuário interativo

Um diferencial deste dashboard é a correlação entre eventos `DnsRequest` (que registram apenas o usuário do processo, frequentemente `SYSTEM`) e os eventos `UserLogon` / `UserIdentity` (que registram o usuário humano interativo logado no host). Isso permite responder à pergunta crítica: **"quem foi a pessoa por trás desse acesso?"** — informação essencial para conversas com gestores e RH em casos de Shadow IT.

A correlação é feita via `defineTable` aninhado nas queries dos widgets **"Acessos por Usuário"** e **"Detalhamento Completo"**.

---

## Instalação

### Pré-requisitos

- Acesso ao **CrowdStrike Falcon Next-Gen SIEM**
- Permissão para criar e importar dashboards
- Sensor Falcon coletando eventos `DnsRequest`, `UserLogon` e `UserIdentity` dos hosts (padrão na maioria das tenants)

### Passo a passo

1. Faça download do arquivo `falcon-ai-watch.yaml` deste repositório.
2. No console do Falcon, acesse **Next-Gen SIEM → Dashboards**.
3. Clique nos três pontos no canto superior direito e selecione **Import dashboard** (ou opção equivalente conforme sua versão).
4. Faça upload do arquivo YAML.
5. Confirme a importação.
6. O dashboard estará disponível com o nome **"Monitoramento de Acessos para domínios de IA"**.

### Ajustes pós-importação

- **Janela de tempo padrão** está em `2d` — ajuste conforme a relevância do seu contexto.
- **Adicionar/remover plataformas** conforme a realidade da sua organização (ferramentas como Cognition Devin, GitHub Copilot Workspace e outras podem ser incluídas).

---

## Como usar

1. Abra o dashboard.
2. No topo, selecione a plataforma desejada no dropdown **"Plataformas de IA"**.
3. Clique em **Apply**.
4. Os 8 widgets atualizam automaticamente refletindo apenas a plataforma escolhida.
5. Ajuste a janela de tempo no canto superior direito conforme necessário.

---

## Queries utilizadas

Todas as queries seguem o padrão de filtro com wildcard para capturar tanto o domínio raiz quanto subdomínios:

```
#event_simpleName=DnsRequest DomainName=*?dominios
```

A sintaxe `?dominios` (com uma única interrogação no início) é a forma como o LogScale referencia parâmetros dentro de queries. O wildcard `*` antes do parâmetro garante que subdomínios sejam capturados (ex.: `app.lovable.dev`, `cdn.lovable.dev`).

### Exemplo — KPI de Hosts Únicos

```
#event_simpleName=DnsRequest
| DomainName=*?dominios
| count(ComputerName, as=TotalHosts, distinct=true)
```

### Exemplo — Top Hosts

```
#event_simpleName=DnsRequest DomainName=*?dominios
| groupBy([ComputerName, aid], function=([count(DomainName, as=DominiosUnicos, distinct=true), count(as=Requisicoes)]))
| sort(Requisicoes, order=desc, limit=25)
```

### Exemplo — Acessos por Usuário (com identificação de usuário interativo)

```
defineTable(
  name="logon_lookup",
  query={
    #event_simpleName=/^(UserLogon|UserIdentity)$/
    | UserName=*
    | groupBy([ComputerName], function=selectLast([UserName]))
    | rename(field=UserName, as=LoggedUser)
  },
  include=[ComputerName, LoggedUser]
)
| #event_simpleName=DnsRequest DomainName=*?dominios
| match(table="logon_lookup", field=ComputerName, strict=false)
| default(field=LoggedUser, value="-")
| LoggedUser!="-"
| groupBy([LoggedUser, DomainName], function=count(as=Acessos))
| sort(Acessos, order=desc)
```

### Exemplo — Detalhamento completo

```
defineTable(
  name="logon_lookup",
  query={
    #event_simpleName=/^(UserLogon|UserIdentity)$/
    | UserName=*
    | groupBy([ComputerName], function=selectLast([UserName]))
    | rename(field=UserName, as=LoggedUser)
  },
  include=[ComputerName, LoggedUser]
)
| #event_simpleName=DnsRequest DomainName=*?dominios
| groupBy([DomainName, ComputerName, UserName, FileName], function=([count(as=Requisicoes), max(@timestamp, as=UltimoAcesso)]))
| match(table="logon_lookup", field=ComputerName, strict=false)
| UltimoAcesso := formatTime(format="%Y-%m-%d %H:%M:%S", field=UltimoAcesso)
| default(field=LoggedUser, value="-")
| table([DomainName, LoggedUser, ComputerName, UserName, FileName, Requisicoes, UltimoAcesso])
| sort(Requisicoes, order=desc)
```

---

## Limitações conhecidas

- **Cache DNS do sistema operacional** — nem todo acesso gera evento `DnsRequest`. Se o domínio já foi resolvido recentemente, o SO usa o cache e não dispara nova consulta. O volume real de uso pode ser maior do que o apontado pelo dashboard.
- **DNS sobre HTTPS (DoH)** — navegadores configurados para usar DoH (Chrome, Firefox, Edge) **não geram eventos `DnsRequest` visíveis ao sensor**. Em organizações com DoH habilitado, considere também ingerir logs do proxy/firewall corporativo.
- **VPN corporativa com DNS interno** — se o tráfego DNS é direcionado a resolvers internos, garanta que esses resolvers também estejam sendo monitorados.
- **Sensor offline** — eventos só são reportados quando o host está online ou quando reconecta com a Falcon Cloud. Períodos de offline podem aparecer como gaps na linha do tempo.
- **Identificação de usuário interativo** — em hosts que não receberam novo `UserLogon` ou `UserIdentity` na janela selecionada (máquinas que ficam ligadas há semanas, servidores), o usuário aparece como `-`. Ampliar a janela de tempo do dashboard pode reduzir esses casos.
- **GitHub Copilot** — não é monitorado por este dashboard via DNS porque o tráfego passa por `github.com` (compartilhado com uso normal do GitHub). Para monitorar Copilot, considere fontes alternativas como GitHub Enterprise audit logs ou eventos de processo.

---

## Roadmap

Melhorias planejadas para próximas versões:

- [ ] **Alerta de detecção** — disparar notificação quando um novo host (que nunca acessou antes) começa a usar uma das plataformas
- [ ] **Enriquecimento com processo de origem** — identificar se o acesso foi via navegador, IDE com plugin de IA, ou CLI
- [ ] **Correlação com eventos de upload** — detectar transferências de arquivos para domínios das plataformas
- [ ] **Inclusão de mais plataformas** — Cognition Devin, GitHub Copilot Workspace (via fontes alternativas)
- [ ] **Visão por departamento** — agrupar acessos por OU/grupo do Active Directory
- [ ] **Exportação executiva** — relatório PDF semanal automatizado para o CISO

---

## Referências

- [CrowdStrike Falcon LogScale Query Language](https://library.humio.com/data-analysis/syntax.html)
- [Falcon Event Schema — Documentação oficial](https://falcon.crowdstrike.com/documentation)
