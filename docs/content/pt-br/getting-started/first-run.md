---
title: Sua Primeira Execução
description: Caminhe pela sua primeira sessão de watch, entenda a saída de dry-run e arme o EzyShield
order: 3
---

# Sua Primeira Execução

Após a instalação, você configurou o EzyShield com pelo menos uma fonte de log. Agora vamos executá-lo pela primeira vez e entender o que ele está fazendo.

## Passo 1: Comece em dry-run (padrão)

Por padrão, o EzyShield roda em modo **dry-run** — analisa logs e toma decisões, mas nunca bloqueia nada. Isso é intencional: observe primeiro, arme depois.

```bash
sudo ezyshield run
```

Você verá uma saída como esta:

```
2026-07-08T10:15:23Z INFO starting pipeline
2026-07-08T10:15:24Z INFO collector[journald]: started
2026-07-08T10:15:24Z INFO collector[file]: tailing /var/log/nginx/access.log
2026-07-08T10:15:30Z WARN decision: ssh brute-force attempt from 203.0.113.42 (strike 1, score 95)
  verdict: dry_ban (would ban for 5 minutes)
```

Repare no veredito `dry_ban` — aquele IP teria sido bloqueado, mas em dry-run apenas fica registrado no log.

## Passo 2: Leia a saída do dry-run

Cada linha de veredito informa:
- **O ataque**: brute-force de SSH, scraping de login do WordPress etc.
- **O IP do atacante**: 203.0.113.42
- **Contagem de strikes e score**: quantas vezes esse IP já atacou e o nível de confiança
- **A ação**: `dry_ban` (o que aconteceria se estivesse armado) ou `allow` (bateu na allowlist)

Rode por 24 horas em dry-run e monitore:
- Falsos positivos: IPs legítimos recebendo score alto
- Cobertura: quais padrões de ataque estão sendo detectados
- Ruído: quantos eventos por minuto

## Passo 3: Confira a trilha de auditoria

Veja o que teria sido bloqueado:

```bash
ezyshield report | head -30
```

`report` mostra o histórico de decisões por IP (strikes, scores, evidências) sem
que nada seja de fato bloqueado.

## Passo 4: Arme

Quando estiver confiante, edite `policy.yaml`:

```yaml
armed: true
```

Depois recarregue o daemon:

```bash
sudo systemctl restart ezyshield
```

O EzyShield agora bloqueia em tempo real: os bans vão para o nftables (local) e para o Cloudflare (borda), e as notificações são enviadas.

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
sudo ezyshield ban 203.0.113.42         # Banir permanentemente
sudo ezyshield unban 203.0.113.42       # Desbanir
sudo ezyshield allow 198.51.100.0/24    # Adicionar um CIDR à allowlist
```

## Próximos passos

- Leia a [Referência de Config](../reference/config.md) para ajustar os thresholds
- Explore os [Guias](../guides/cloudflare.md) para a integração Cloudflare + nftables
- Consulte [Segurança](../security/overview.md) para entender as garantias
