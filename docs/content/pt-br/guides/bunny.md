---
title: Implantando na bunny.net
description: Bloqueie IPs na borda com pull zones da bunny.net
order: 2
---

# Enforcement de Borda bunny.net

Bloqueie IPs maliciosos na borda da bunny.net. Quando seu servidor está
atrás da bunny.net, o firewall só enxerga os IPs de edge da bunny na
camada TCP — um ban de nftables no IP real do cliente nunca casa. O
enforcer bunny fecha essa lacuna empurrando cada ban para a lista de IPs
bloqueados das suas pull zones.

## Como funciona

O EzyShield usa a API de blocked-IPs das pull zones (funciona em
**qualquer plano da bunny.net**, sem assinatura do Bunny Shield):

- **Ban** adiciona o IP à lista de bloqueio de cada pull zone configurada.
- **Unban** o remove.
- No startup e periodicamente, o **Sync** reconcilia a lista de cada zona
  para exatamente o conjunto de bans ativos — entradas faltantes são
  adicionadas, obsoletas removidas.

> **O EzyShield é dono da lista.** A lista de IPs bloqueados da bunny é
> plana, sem como marcar entradas, então o EzyShield assume a propriedade
> dela nas zonas configuradas: IPs que você bloquear **manualmente no
> painel da bunny são removidos no próximo reconcile**. Mantenha bloqueios
> manuais em uma zona que o EzyShield não gerencia, ou deixe o EzyShield
> bloquear por você.

## Configuração

### 1. Encontre a API key e os IDs das pull zones

- **API key**: painel da bunny → **Account** → **API**. É a chave de
  conta (a bunny.net não tem tokens com escopo para a API de pull zone
  hoje — veja Considerações de Segurança abaixo).
- **IDs das pull zones**: painel → **CDN** → abra a pull zone — o ID
  numérico está na URL (ex.: `.../pullzone/123456`).

### 2. Configure

O wizard `ezyshield init` oferece esta configuração quando detecta a
bunny.net na frente dos seus domínios (ou quando você responde sim à
pergunta sobre CDN). Para configurar manualmente:

```yaml
# /etc/ezyshield/config.yaml
enforce:
  nftables: {}          # mantenha o enforcement local também
  bunny:
    api_key: env:BUNNY_API_KEY
    pull_zones:
      - 123456
      - 234567
```

A chave vive em `/etc/ezyshield/.env` (modo 0600), nunca no config.yaml:

```bash
echo 'BUNNY_API_KEY=sua-chave-aqui' | sudo tee -a /etc/ezyshield/.env
sudo chmod 600 /etc/ezyshield/.env
```

### 3. Dry-run primeiro

Como todo enforcer, o bunny respeita `armed: false` no policy.yaml (o
padrão): as decisões são logadas e armazenadas, mas nada é enviado à
borda. Acompanhe com `ezyshield watch` por um dia e então arme:

```bash
sudo ezyshield arm
```

### 4. Verifique

```bash
sudo ezyshield doctor        # checa a chave + cada pull zone (somente leitura)
```

## Limites

- **500 IPs por pull zone** (cap conservador do próprio EzyShield — a
  bunny não documenta um limite do provider). Acima disso, os bans mais
  recentes vencem: o `Sync` mantém os mais novos, e um ban novo no cap
  evita o mais antigo, com warning claro nos logs.
- Chamadas de API são limitadas a 4 requisições/segundo e repetidas com
  backoff em 429/5xx.
- IPv6: o EzyShield envia bans IPv6 como qualquer outro; a documentação
  da bunny não declara suporte a IPv6 explicitamente, então uma rejeição
  é logada e pulada sem quebrar o reconcile.

## Solução de problemas

| Sintoma | Causa | Correção |
|---|---|---|
| `doctor` falha "key rejected (HTTP 401)" | chave rotacionada ou digitada errada | copie a chave de Account → API para `/etc/ezyshield/.env` e reinicie o daemon |
| `doctor` falha "pull zone not found (HTTP 404)" | ID numérico errado | confira o ID na URL da pull zone no painel |
| bloqueios manuais do painel somem | o EzyShield reconciliou a lista | esperado — veja "O EzyShield é dono da lista" acima |
| bans funcionam localmente mas atacantes ainda acessam via bunny | `enforce.bunny` ausente ou chave não resolvida no startup | procure "bunny enforcer unavailable" no `journalctl -u ezyshield` |

## Considerações de Segurança

- A API key é **de conta** — gerencia tudo na sua conta bunny. Trate como
  credencial root: `.env` modo 0600, nunca no config.yaml (o loader
  rejeita valores inline), nunca em logs (o EzyShield nunca a imprime, e a
  ausência dela nas mensagens de erro é coberta por testes).
- Toda resposta da API é tratada como entrada não confiável: leituras
  limitadas, decode tipado, entradas não-IP da lista remota ignoradas.
- A allowlist é aplicada antes de qualquer ban chegar à bunny (Hard Rule §1).

## Veja Também

- [Enforcement de Borda Cloudflare](cloudflare.md) — o enforcer irmão;
  os dois podem rodar juntos em setups multi-CDN.
- [Referência de Config](../reference/config.md#bunny)
