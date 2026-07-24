---
title: Sua Primeira Execução
description: Caminhe pela sua primeira sessão de watch, entenda a saída de dry-run e arme o EzyShield
order: 3
---

# Sua Primeira Execução

Após a instalação, você configurou o EzyShield com pelo menos uma fonte de log. Agora vamos executá-lo pela primeira vez e entender o que ele está fazendo.

## Passo 1: Comece em dry-run (padrão)

Por padrão, o EzyShield roda em modo **dry-run** — analisa logs e toma decisões, mas nunca bloqueia nada. Isso é intencional: observe primeiro, arme depois.

O dry-run espelha exatamente a semântica do modo armado: um `dry_ban` registra
o strike e um **ban simulado** com o mesmo TTL que um ban real teria, e novos
eventos daquele IP são suprimidos até o TTL simulado expirar — a escalada que
você observa (strike 1 → 2 → 3 …) é exatamente a que a produção aplicaria.
Nada é jamais aplicado no firewall: bans simulados nunca chegam ao enforcer, e
o `ezyshield status` os reporta separados dos bans ativos.

```bash
sudo ezyshield run
```

O daemon registra linhas JSON estruturadas no stderr. Uma decisão em dry-run
se parece com isto:

```json
{"time":"2026-07-08T10:15:30Z","level":"INFO","msg":"decision: dry_ban (armed=false)","ip":"203.0.113.42","would_strike":1,"would_ttl":300000000000}
```

Repare no veredito `dry_ban` — aquele IP teria sido bloqueado, mas em dry-run apenas fica registrado no log. `would_ttl` está em nanossegundos (codificação padrão de duração do slog); `300000000000` equivale a 5 minutos.

## Passo 2: Leia a saída do dry-run

Cada linha de veredito informa:
- **O ataque**: brute-force de SSH, scraping de login do WordPress etc.
- **O IP do atacante**: 203.0.113.42
- **Contagem de strikes e score**: quantas vezes esse IP já atacou e o nível de confiança
- **A ação**: `dry_ban` (o que aconteceria se estivesse armado) ou `allow` (bateu na allowlist)
- Novos hits durante um ban simulado aparecem como `already_banned` — um episódio, um strike, exatamente como no modo armado

Rode por 24 horas em dry-run e monitore:
- Falsos positivos: IPs legítimos recebendo score alto
- Cobertura: quais padrões de ataque estão sendo detectados
- Ruído: quantos eventos por minuto

## Passo 3: Confira a trilha de auditoria

Veja o que teria sido bloqueado:

```bash
ezyshield report | head -30
```

Sem um argumento de IP, `report` lista todos os ofensores registrados em uma
tabela resumo (`IP`, `FIRST SEEN`, `LAST SEEN`, `STRIKES`, `BANNED`,
`COUNTRY`, `ASN`) — nada é de fato bloqueado. Para o histórico completo de
decisões por IP (strikes, scores, evidências), passe um IP:

```bash
ezyshield report 203.0.113.42
```

## Passo 4: Arme

Quando estiver confiante, arme com o comando dedicado — sem editar config,
sem restart:

```bash
sudo ezyshield arm
```

O `arm` roda um pre-flight obrigatório antes de mudar qualquer coisa:
saúde do enforcer, cobertura de `admin_cidrs`/allowlist, uma simulação de
"eu baniria a mim mesmo?" com o IP da sua sessão SSH, e um resumo da
atividade recente em dry-run. Checks reprovados recusam a transição
(`--force` sobrepõe tudo, exceto o check de auto-ban — esse nunca é
contornável).

O jeito mais seguro de armar pela primeira vez é com janela de
auto-reversão:

```bash
sudo ezyshield arm --for 1h
```

Pela próxima hora o EzyShield aplica bans de verdade. Se tudo estiver bem,
torne permanente:

```bash
sudo ezyshield arm --keep
```

Se você não fizer nada — ou se tiver se trancado fora e não *puder* fazer
nada — o daemon reverte sozinho para dry-run quando a janela expira e
envia uma notificação. A reversão roda dentro do daemon, então dispara
mesmo que a sua sessão SSH tenha caído.

As duas transições são persistidas no `policy.yaml` e registradas no audit
log; `sudo ezyshield disarm` volta para dry-run a qualquer momento.

Armado, o EzyShield bloqueia em tempo real: os bans vão para o nftables
(local) e para o Cloudflare (borda), e as notificações são enviadas.

## Passo 5: Monitore os bans ativos

```bash
ezyshield list           # bans ativos
ezyshield list --allow   # entradas da allowlist
ezyshield status
```

Veja o que está banido, sua allowlist e a saúde do daemon.

## Solução de problemas

**P: Meu tráfego legítimo está sendo bloqueado**

R: Adicione-o à allowlist em `policy.yaml`:

```yaml
allowlist:
  - 198.51.100.0/24    # seu escritório
  - 192.0.2.100        # um usuário específico
```

Aplique a mudança com um restart:

```bash
sudo systemctl restart ezyshield
```

**P: Nenhum evento está sendo detectado**

R: Verifique se as fontes de log estão configuradas e se os logs estão de fato sendo escritos:

```bash
sudo ezyshield doctor
tail -f /var/log/auth.log      # Para SSH
tail -f /var/log/nginx/access.log  # Para Nginx
```

**P: Quero banir/desbanir manualmente**

R:

```bash
sudo ezyshield ban 203.0.113.42 --ttl 0  # ttl=0 = permanente (sem expiração)
sudo ezyshield unban 203.0.113.42        # Desbanir
sudo ezyshield allow 198.51.100.0/24     # Adicionar um CIDR à allowlist
```

## Próximos passos

- Leia a [Referência de Config](../reference/config.md) para ajustar os thresholds
- Explore os [Guias](../guides/cloudflare.md) para a integração Cloudflare + nftables
- Consulte [Segurança](../security/overview.md) para entender as garantias
