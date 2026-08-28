---
title: Coexistência de Firewalls
description: Rodando o EzyShield junto com ufw ou firewalld
order: 9
---

# Coexistência de Firewalls (ufw / firewalld)

Muitos hosts já rodam ufw ou firewalld. O EzyShield foi projetado para coexistir com eles: nunca toca nas regras deles, e eles normalmente nunca tocam nas do EzyShield. Esta página explica como a interação funciona, com o que se preocupar, e como o `ezyshield doctor` detecta conflitos reais.

## Como a coexistência funciona

O EzyShield gerencia sua **própria** tabela nftables — `inet ezyshield` — criada pelo helper `ezyshield-enforcer`. Nada mais escreve nela, e o EzyShield não escreve em nenhum outro lugar.

- **Prioridade do hook.** As regras de drop do set de bloqueio se prendem na prioridade `raw` — *antes* das chains de filter do ufw e do firewalld. Um IP banido é descartado antes de o outro firewall sequer ver o pacote; para todos os outros pacotes, as chains do EzyShield aceitam e o seu firewall aplica a política dele sem mudança.
- **Tabelas independentes.** Tabelas nftables têm namespace próprio. `ufw reload` e `firewall-cmd --reload` reescrevem as tabelas *deles* e normalmente deixam tabelas alheias (como a nossa) em paz. O inverso também vale.
- **Allowlist primeiro.** Dentro da tabela do EzyShield, ranges em allowlist aceitam antes de qualquer drop — a opinião do outro firewall sobre esses IPs não é afetada em nenhum caso.

## Com o que se preocupar

- **Flush total do ruleset apaga nossa tabela.** `nft flush ruleset` (alguns scripts de hardening), reiniciar o `nftables.service` com um `/etc/nftables.conf` estático, ou scripts estilo `iptables -F` em backends iptables-nft podem limpar **todas** as tabelas — inclusive a `inet ezyshield`. Os bans continuam registrados no store do EzyShield, mas nada é aplicado até o enforcer recriar a tabela. Esse é o único conflito *real*, e o doctor falha alto nele (abaixo).
- **Gerência duplicada.** Banir o mesmo IP nas duas ferramentas funciona, mas confunde a auditoria: o outro firewall pode logar/rejeitar um pacote que o EzyShield teria descartado um hook antes, ou vice-versa. Prefira deixar bans de atacantes com o EzyShield e a política de serviços (portas abertas/fechadas) com o seu firewall.
- **Ordem no boot.** As units distribuídas iniciam o enforcer antes do daemon; ufw/firewalld iniciam quando quiserem — a ordem não importa, porque as tabelas são independentes.

## O que o doctor verifica

```console
$ sudo ezyshield doctor
[PASS] firewall: coexistence
       hint: ufw active alongside EzyShield -- coexistence works: ...
[FAIL] firewall: ezyshield nftables table
       hint: 5 active ban(s) recorded but the ezyshield nftables table is GONE -- nothing is being enforced. ...
```

- `firewall: coexistence` — detecta ufw/firewalld ativos (via estado da unit no systemd, somente leitura; o doctor nunca executa os CLIs deles) e explica a interação.
- `firewall: ezyshield nftables table` — o detector de conflito. **FAIL** quando há bans ativos registrados mas a tabela sumiu: o enforcement está silenciosamente ausente. **WARN** quando a tabela está ausente sem bans registrados (nada foi perdido ainda). Precisa de root para listar tabelas; sem isso o check reporta N/A.

## Recuperando de uma tabela apagada

```bash
sudo systemctl restart ezyshield-enforcer ezyshield
sudo ezyshield doctor        # o check da tabela deve voltar a PASS
```

O enforcer recria a tabela ao iniciar, e o daemon re-sincroniza cada ban ativo a partir do store — nada se perde enquanto o store estiver intacto (o reconcile periódico também repara o drift sozinho em minutos).

O EzyShield nunca edita, recarrega ou migra regras do ufw/firewalld — coexistência é só detecção e relato honesto.
