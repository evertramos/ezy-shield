---
title: Solução de Problemas
description: As perguntas comuns de falha, cada uma com o check do doctor que diagnostica
order: 14
---

# Solução de Problemas

As quatro perguntas que cobrem a maioria dos casos de suporte. Comece toda sessão do mesmo jeito:

```bash
sudo ezyshield doctor
```

O doctor é somente leitura e cada check imprime uma **dica com o fix exato**. As seções abaixo mapeiam os sintomas comuns aos checks que os diagnosticam.

## "O daemon roda mas nada é detectado"

Detecção precisa de uma fonte de log, um parser compatível e eventos de fato fluindo.

1. **`collectors: configured`** (doctor) — zero collectors significa que nada é lido, nunca. Adicione uma seção `collectors:` (ou re-rode `ezyshield init`).
2. **`journald: readable`** (doctor) — o collector journald roda como o usuário `ezyshield`, que precisa do grupo `systemd-journal`. A dica traz o `usermod` do fix.
3. **Unit ou path errado.** Debian chama a unit de SSH de `ssh`, RHEL de `sshd`; um collector `file` precisa do log de *access* para as regras HTTP. Compare sua config com o que realmente loga: `sudo ezyshield scan` lista serviços escutando e suas fontes de log.
4. **Ainda em silêncio?** `ezyshield status` mostra `CollectorsState: DEGRADED` com o collector falhando nomeado quando uma fonte erra repetidamente; `ezyshield watch` confirma eventos no momento em que o parsing funciona.

## "Um ban foi registrado mas o IP não está bloqueado"

O pior modo de falha — e o mais instrumentado.

1. **`ezyshield status`** primeiro: `EnforcementState` é a resposta honesta. `DRY-RUN` significa `armed: false` — bans registrados são *simulados* por design. `DEGRADED` nomeia o backend falhando.
2. **`enforcer: socket connectivity`** (doctor) — o helper está fora ou o socket inacessível: `systemctl status ezyshield-enforcer`.
3. **`enforcer: netlink probe`** (doctor) — o helper roda mas o sandbox perdeu acesso a netlink (unit modificada): a dica nomeia o fix de `RestrictAddressFamilies`.
4. **`firewall: ezyshield nftables table`** (doctor) — a tabela SUMIU com bans ativos: algo fez flush do ruleset (veja o [guia de coexistência de firewalls](firewall-coexistence.md)); `systemctl restart ezyshield-enforcer ezyshield` recria e re-sincroniza.
5. **`bans: ban_ineffective diagnostics`** (doctor) — o próprio daemon marca bans que continuaram gerando eventos após o período de graça.

## "Erros de permissão no socket"

```
dial unix /run/ezyshield/ezyshield.sock: connect: permission denied
```

O socket de controle é `root:ezyshield`, modo `0660` — pertencer ao grupo `ezyshield` é o controle de acesso.

1. `id` — você está no grupo `ezyshield`? O `ezyshield init` adiciona o admin que instalou; para os demais: `sudo usermod -aG ezyshield <user>` e re-login.
2. Socket ausente → o daemon não está rodando (`systemctl status ezyshield`); `exit code 3` em qualquer comando da CLI significa exatamente "daemon inacessível".
3. **`ezyshield-enforcer.service: runtime directory`** / **`ezyshield.service: runtime directory`** (doctor) — uma unit despida nunca cria `/run/ezyshield*`; a dica traz o drop-in do fix.

## "A fonte journald não é capturada"

Eventos existem no `journalctl -u ssh` mas o EzyShield não vê nada.

1. O `unit:` do collector precisa bater com o nome *exato* da unit — `ssh` vs `sshd` de novo. `systemctl list-units 'ssh*'` resolve.
2. **`journald: readable`** (doctor) — lê o journal *com a identidade do daemon*; um PASS aqui com silêncio geralmente é o nome da unit.
3. Setups com container: o journald dentro do container não é o journal do host — rode o collector onde os logs estão, ou use um collector `file` num log montado.

## Caminhos de escalação

- Falso positivo banindo usuários reais → `sudo ezyshield allow <ip>` (allowlist sempre vence), depois ajuste via `rules.d`.
- Tudo pegando fogo → `sudo ezyshield disable --all` (remove todo bloqueio, desarma, mantém histórico — veja a [referência de CLI](../reference/cli.md)).
- Bug reports: anexe a saída de `ezyshield doctor --json` e `ezyshield status --json` — ambas seguras de compartilhar (sem segredos).
