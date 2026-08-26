---
title: Benchmark de Detecção
description: Números reprodutíveis de taxa de detecção e falso positivo em corpus rotulado
order: 9
---

# Benchmark de Detecção

A suíte e2e prova que o pipeline se monta; este benchmark prova que as **decisões são boas** — e as protege contra regressão. Ele roda o pipeline de detecção completo (parse → agregação → regras → decisão, dry-run, só regras) sobre um corpus rotulado e reporta taxa de detecção, falsos positivos e tempo-até-o-primeiro-strike.

```bash
make bench        # = go test -tags bench ./internal/bench/ -v
```

## Metodologia

- **Corpus**: cenários rotulados em `fixtures/bench/corpus/`, um YAML por cenário. Todo o tráfego é **sintético mas com formato real** (linhas de log nos formatos exatos que os parsers veem em produção); IPs vêm apenas de ranges de documentação (RFC 5737) — nunca dados reais de usuários.
- **Regras de rotulagem**: um cenário é `attack` quando um operador humano gostaria que a origem fosse banida (brute force, scanning, sondas de exploit) e lista seus `attacker_ips`; é `legit` quando banir seria um falso positivo (logins normais com typo, crawlers bem-comportados, API clients ativos, um admin usando wp-login). Ataques precisam ser *pegos*; cenários legit não podem produzir **nenhuma decisão de banda de ban**.
- **Determinismo**: cada cenário reproduz num relógio virtual (época fixa + `interval_ms` por linha); timestamps do parser são sobrescritos com o tempo virtual, então os resultados são idênticos entre máquinas e execuções. A camada de AI nunca é consultada (só regras, por design); nada é aplicado (policy dry-run, sem enforcer).
- **Métricas**: `detection_rate` = ataques detectados / cenários de ataque; `false_positives` = cenários legit que produziram qualquer decisão de banda de ban; `time_to_first_strike_sec` = segundos virtuais do início do cenário até a primeira decisão.
- **Gate de regressão**: `fixtures/bench/baseline.json` é o contrato commitado. O CI falha quando a taxa de detecção cai, uma detecção do baseline some, ou um falso positivo aparece. Mudanças no baseline são diffs explícitos e revisáveis.

## Números atuais

Na introdução do corpus (10 cenários):

| Métrica | Valor |
|---|---|
| Taxa de detecção | **6/6 ataques (100%)** |
| Falsos positivos | **0/4 cenários legit** |

| Cenário | Label | Resultado | Tempo até 1º strike | Regra |
|---|---|---|---|---|
| attack-ssh-burst | attack | detectado | 8s | ssh_bruteforce |
| attack-ssh-sustained | attack | detectado | 36 min | ssh_bruteforce_sustained |
| attack-wp-scan | attack | detectado | 10s | http_wp_probe |
| attack-env-probe | attack | detectado | 0s | http_env_probe |
| attack-rce-probe | attack | detectado | 0s | http_rce_probe |
| attack-404-scan | attack | detectado | 19s | http_scanner |
| legit-ssh-typo | legit | limpo | — | — |
| legit-crawler | legit | limpo | — | — |
| legit-api-client | legit | limpo | — | — |
| legit-admin-wp | legit | limpo | — | — |

100% em 10 cenários é um **piso sendo guardado**, não uma alegação de marketing: o corpus é pequeno e cresce com o tempo; cada adição roda contra o conjunto de regras inteiro.

## Contribuindo um cenário

1. Adicione um YAML em `fixtures/bench/corpus/`:

   ```yaml
   name: attack-meu-cenario          # único, kebab-case, prefixo attack-/legit-
   description: uma frase honesta
   label: attack                     # attack | legit
   source: "file:/var/log/nginx/access.log"   # seleciona o parser
   attacker_ips: ["203.0.113.99"]    # obrigatório para ataques
   interval_ms: 1000                 # espaçamento virtual entre linhas
   lines:
     - '203.0.113.99 - - [01/Jan/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 162 "-" "ua"'
   ```

2. Use **apenas** IPs de documentação RFC 5737 / RFC 3849, e conteúdo sintético — nunca cole logs reais com dados reais de usuários.
3. Rode `make bench`; ele vai falhar pedindo para adicionar o cenário ao `fixtures/bench/baseline.json` — esse diff é a superfície de revisão.
4. Um ataque que as regras *não pegam* também é contribuição legítima: registre-o no baseline como `false` com um comentário no PR; ele vira o alvo de uma melhoria de regra.
