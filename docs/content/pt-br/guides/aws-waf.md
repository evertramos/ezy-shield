---
title: Deploy no AWS WAF
description: Bloqueie IPs na edge da AWS com IPSets do WAFv2 (CloudFront/ALB)
order: 1
---

# Enforcement de Edge no AWS WAF

Bloqueie IPs maliciosos na edge da AWS. Quando o tráfego entra por
CloudFront ou por um Application Load Balancer, o firewall da origem só vê
endereços da AWS na camada TCP — um ban local no nftables não barra o
atacante na porta. O enforcer AWS WAF mantém **IPSets** dedicados do WAFv2
(um IPv4, um IPv6) que as regras do seu WebACL referenciam, então os bans
valem na edge.

**Fronteira de propriedade**: o EzyShield só atualiza os *endereços
membros* dos IPSets que você designa na config. Ele nunca cria, apaga ou
modifica WebACLs, regras ou qualquer outro recurso do WAF — você continua
no controle de como (block, count, CAPTCHA) e onde os sets são aplicados.

## 1. Crie os IPSets e a regra no WebACL

No console da AWS (WAF & Shield → IP sets), crie dois IP sets vazios:

- `ezyshield-v4` — IP version: IPv4
- `ezyshield-v6` — IP version: IPv6
- Scope: **Regional** (ALB/API Gateway; escolha sua região) ou
  **CloudFront** (global — criado em us-east-1)

Depois adicione uma regra ao seu WebACL: *"Se o IP da requisição origina
do IP set `ezyshield-v4` (ou `ezyshield-v6`) → Block"*. Anote o **Name** e
o **Id** de cada set (ambos aparecem no console; o Id é o UUID no ARN).

## 2. Política IAM (mínima, do ADR-0012)

As credenciais que o EzyShield usa precisam exatamente disto — restrito
aos dois IPSets, nada mais (substitua REGION/ACCOUNT/ID4/ID6; para scope
CloudFront o segmento do ARN é `global/ipset/...` e a região no ARN é
us-east-1):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EzyShieldIPSetMaintenance",
      "Effect": "Allow",
      "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
      "Resource": [
        "arn:aws:wafv2:REGION:ACCOUNT:regional/ipset/ezyshield-v4/ID4",
        "arn:aws:wafv2:REGION:ACCOUNT:regional/ipset/ezyshield-v6/ID6"
      ]
    }
  ]
}
```

Nunca conceda ao enforcer `CreateIPSet`, permissão de WebACL, nem recurso
wildcard.

## 3. Credenciais — nunca na config do EzyShield

Credenciais vêm da **cadeia padrão da AWS**, nesta ordem:

1. Env vars: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
   (+ `AWS_SESSION_TOKEN`) — no systemd, coloque em
   `/etc/ezyshield/ezyshield.env` (modo 0600)
2. Arquivo compartilhado: `~/.aws/credentials` (honra `AWS_PROFILE` e
   `AWS_SHARED_CREDENTIALS_FILE`)
3. Instance role de EC2 via IMDSv2

Elas **nunca** vão para o `config.yaml` — a validação rejeita qualquer
coisa com cara de chave colada, e a seção de config nem tem campos de
credencial. Fluxos de login SSO e AssumeRole no cliente não são
suportados (ADR-0012): gere credenciais de sessão externamente e forneça
via env vars ou o arquivo compartilhado.

## 4. Configure o EzyShield

O `ezyshield init` oferece o AWS WAF no passo de CDN/edge (validando
credenciais e `GetIPSet` em cada set antes de escrever qualquer coisa), ou
adicione a seção à mão:

```yaml
enforce:
  aws_waf:
    scope: regional          # ou: cloudfront (global; região fixa us-east-1)
    region: eu-west-1        # obrigatório para scope: regional
    ipset_v4:
      name: ezyshield-v4
      id: aaaabbbb-cccc-dddd-eeee-ffff00001111
    ipset_v6:
      name: ezyshield-v6
      id: aaaabbbb-cccc-dddd-eeee-ffff00002222
```

Depois verifique e (de início) fique em dry-run:

```bash
ezyshield doctor        # checa credenciais + GetIPSet em cada set designado
ezyshield status        # confirma o daemon com o enforcer anexado
```

**Dry-run primeiro**: com `armed: false` (o default) os bans são simulados
e logados, e nada é enviado à AWS. Acompanhe com `ezyshield watch` por um
dia e então rode `ezyshield arm`.

## Notas de capacidade e comportamento

- **10.000 endereços por IPSet** (limite da AWS). Além disso, o EzyShield
  mantém os bans mais recentes e loga um warning alto sobre o que foi
  descartado.
- Toda mutação é read-modify-write com o lock otimista do WAFv2
  (`LockToken`); editores concorrentes são re-tentados contra uma leitura
  fresca. Evite apontar duas instâncias do EzyShield para os mesmos
  IPSets.
- Endereços são sempre normalizados como CIDR (`/32`, `/128`); IPv4
  mapeado em IPv6 cai no set v4.
- Família sem IPSet designado é pulada com warning — o nftables local
  continua cobrindo na origem.
- A allowlist é checada antes de qualquer chamada de API, e o gate central
  de allowlist/anti-lockout do daemon roda na frente deste enforcer como
  de todos os outros — um endereço protegido nunca chega à AWS.
- A avaliação da regra do WAF é na edge; a origem ainda recebe o tráfego
  que a AWS deixa passar — mantenha o enforcement local como segunda
  camada.
