---
title: Bots Verificados
description: Protegendo crawlers legítimos com reverse DNS de confirmação direta
order: 9
---

# Proteção de Bots Verificados

O anti-lockout protege *você*; nada protegia ainda os crawlers legítimos de uma regra agressiva demais. Banir o Googlebot é um dos falsos positivos mais danosos que um dono de site pode sofrer — a visibilidade na busca degrada em silêncio enquanto todos os dashboards seguem verdes. Este recurso poupa bots conhecidos de bans, com segurança.

## Por que User-Agent sozinho nunca é confiável

Qualquer um pode enviar `User-Agent: Googlebot/2.1` — atacantes fazem isso rotineiramente, justamente porque configurações ingênuas o allowlistam. Uma alegação de UA sozinha não vale nada.

O check padrão da indústria (documentado por Google, Microsoft e Apple como *o* mecanismo de verificação) é o **forward-confirmed reverse DNS** (FCrDNS):

1. **Lookup PTR** no IP conectado → ex.: `crawl-66-249-66-1.googlebot.com`.
2. **Check de domínio**: o nome precisa cair sob os domínios publicados do provedor (`googlebot.com`, `google.com`) — ancorado no ponto, então `evilgooglebot.com` nunca casa.
3. **Confirmação direta**: resolver esse nome de volta e exigir que mapeie para o **mesmo IP**.

Só um IP que passa nas duas direções é tratado como o bot que alega ser. Um spoofer falha no passo 2 ou 3 e segue o caminho normal de ban — alegar ser o Googlebot não muda nada para ele.

## Habilitando

```yaml
# /etc/ezyshield/config.yaml
verified_bots:
  enabled: true
```

Cobertos por padrão: **Googlebot, Bingbot (msnbot), Applebot, YandexBot, Baiduspider, DuckDuckBot.**

## Como se encaixa no pipeline de decisão

- O check roda **apenas em tempo de decisão, para candidatos a ban** — nunca no caminho quente de parse. Sem alegação de bot no tráfego observado do IP → nenhum DNS acontece.
- Ordem: allowlist e anti-lockout continuam rodando primeiro e sempre vencem. O guard de bots só pode converter um ban iminente em um `record` auditado (`verified-bot spared: googlebot` no audit log) — nunca pode causar ou escalar um ban.
- DNS é limitado: timeout de 2s por lookup, contagem de respostas com cap, respostas tratadas como entrada não-confiável. Resultados são cacheados (6h positivo, 15min negativo), então um crawler ativo custa um par de lookups a cada poucas horas.
- **Falha fechado**: timeout de DNS ou qualquer anomalia significa que a alegação é simplesmente ignorada — o caminho normal de ban prossegue. Um resolver inacessível nunca vira isenção de ban.

## Adicionando seu próprio provedor

Monitores de uptime e outras sondas legítimas podem ser adicionados se o operador publica rDNS estável:

```yaml
verified_bots:
  enabled: true
  providers:
    - name: mymonitor
      ua_contains: [MyMonitor]          # substrings case-insensitive
      domains: [monitor.example.com]    # o PTR precisa cair sob este sufixo
```

Entradas são mescladas com as embutidas por `name` — reusar um nome embutido substitui aquela entrada. Só adicione provedores cujo rDNS você pode confiar; um provedor cujos registros PTR não confirmam não ganha nada (e não perde nada — o tráfego dele é só julgado como o de todo mundo).
