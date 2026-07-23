---
title: Implantando no Cloudflare
description: Bloqueie IPs na borda com Cloudflare
order: 1
---

# Bloqueio de IPs na Edge da Cloudflare

Este guia mostra como configurar o EzyShield para bloquear IPs maliciosos na edge da Cloudflare usando o modo **Lists** (recomendado para a maioria das implantações).

## Comparação entre Modos

EzyShield oferece dois modos de bloqueio na Cloudflare:

| Recurso | Lists | Rulesets |
|---------|------------------|-------------------|
| **Chamadas de API por bloqueio** | 1 (account-level) | 1 por zone |
| **Capacidade de IPs** | 10.000 | ~200 por rule |
| **Suporte multi-zone** | Automático | Regras por zone |
| **Configuração WAF** | Automática | Manual por zone |
| **Plano gratuito** | ✅ (1 list, 10k items) | ✅ |
| **Menor privilégio** | ❌ (precisa token account-level) | ✅ (token zone-level) |

Os dois modos são totalmente suportados — escolha por implantação (e, em
configurações multi-conta, por conta). **Lists** atende a maioria das
implantações multi-zone; **rulesets** atende controle por zone, tokens de
menor privilégio (zone-level) ou contas cuja cota de custom lists já está
ocupada. Rodar uma conta em lists e outra em rulesets é uma configuração
perfeitamente normal.

## Configuração do Modo Lists

### Passo 1: Criar Token de API da Cloudflare

1. Acesse [Painel da Cloudflare](https://dash.cloudflare.com)
2. Vá em **Account → API Tokens** (barra lateral, canto inferior esquerdo)
3. Clique em **Create Token** e selecione **Custom token**
4. Configure o token com estas permissões:
   - **Account → Account Filter Lists → Edit** (obrigatório para gerenciar a lista de IPs)
   - Para cada zone que quiser gerenciar regras WAF automaticamente:
     - **Zone → Firewall Services → Edit** (opcional; obrigatório ao usar `zone_ids`)
5. Defina restrições conforme necessário (allowlist de IP, TTL, etc.)
6. Copie o token imediatamente — você não conseguirá vê-lo novamente

### Passo 2: Obter Account ID e Zone IDs

**Account ID:**
- Acesse **Account → Workers** no Painel da Cloudflare
- O Account ID é exibido no canto inferior esquerdo da página (32 caracteres hexadecimais)

**Zone IDs (opcional, para gerenciamento automático de regras WAF):**
- Para cada domínio/zone que quiser proteger
- Vá em **Domain → Overview**
- O Zone ID está na barra lateral direita (32 caracteres hexadecimais)

### Passo 3: Configurar EzyShield

Salve o token de API como variável de ambiente:

```bash
export EZYSHIELD_CF_TOKEN="seu_token_api_aqui"
```

Adicione ao `config.yaml`:

```yaml
enforce:
  cloudflare:
    api_token: env:EZYSHIELD_CF_TOKEN
    mode: lists
    account_id: seu_account_id_32_caracteres_hex
    # Opcional: gerenciar regras WAF automaticamente por zone
    zone_ids:
      - zone_id_1
      - zone_id_2
    # Opcional: ação da regra WAF (padrão: "block")
    action: block  # ou "challenge" / "js_challenge"
    # Opcional: nome customizado da lista (padrão: "ezyshield_blocked")
    # list_name: ezyshield_blocked
```

### Passo 4: Verificar Configuração

Execute o comando de diagnóstico:

```bash
ezyshield doctor cloudflare
```

Este comando irá:
- Verificar se o token de API tem as permissões corretas
- Testar conectividade com a Cloudflare
- Listar zones acessíveis
- Mostrar o status da lista (criada, quantidade de items, etc.)

### Passo 5: (Opcional) Configuração Manual da Regra WAF

**Se você NÃO configurou `zone_ids`** no passo 3, você deve criar a regra WAF Custom manualmente para cada zone:

1. Vá em **Domain → Security → WAF → Custom rules**
2. Clique em **Create Rule**
3. Configure:
   - **Field:** IP Source Address
   - **Operator:** is in list
   - **Value:** Selecione sua lista `ezyshield_blocked`
   - **Action:** Block (ou a ação que você escolheu)
   - **Description:** `ezyshield-list-block`
4. Implante a regra

Se você configurou `zone_ids`, este passo é **automático** — as regras são criadas no primeiro Sync.

## Configuração do Modo Rulesets

Para implantações que querem controle por zone ou não podem usar tokens account-level:

### Passo 1: Criar Token de API de Nível de Zone

1. Vá em **Zone → API Tokens** (no painel da zone)
2. Crie um token com:
   - **Zone → Firewall → Edit** em cada zone
3. Salve o token como `EZYSHIELD_CF_TOKEN`

### Passo 2: Configurar EzyShield

```yaml
enforce:
  cloudflare:
    api_token: env:EZYSHIELD_CF_TOKEN
    mode: rulesets
    zone_ids:
      - zone_1
      - zone_2
    action: block  # ou "challenge" / "js_challenge"
```

Cada zone recebe sua própria regra WAF Custom com todos os IPs bloqueados. Limites de tamanho de expressão (~3900 bytes) significam aproximadamente 200 IPs por regra; EzyShield divide automaticamente em múltiplas regras se necessário.

## Limites de plano e o que o EzyShield verifica

As quotas da Cloudflare dependem do plano, e um token válido não garante um
setup que funcione. Dois limites importam aqui:

- **Custom Lists (modo lists):** o número de listas custom depende do plano —
  **contas free têm uma única lista custom**. Se esse slot já estiver ocupado
  por outra lista, a lista do EzyShield não pode ser criada e o enforcement
  nunca vai funcionar.
- **Regras custom do WAF (ambos os modos):** as regras são limitadas por zona
  por plano (5 no free). O modo lists precisa de uma regra por zona coberta
  referenciando a lista; o modo rulesets escreve suas regras diretamente.

O EzyShield verifica a viabilidade em três momentos, para você descobrir na
hora — não no primeiro sync armado:

1. **No setup** (`init` / `config enforcer cloudflare`): depois de validar o
   token e o escopo, o wizard **cria ou adota** a Custom List configurada ali
   mesmo. Uma recusa por quota aborta o setup mostrando as saídas (apagar uma
   lista sem uso, fazer upgrade do plano, ou trocar para o modo rulesets) —
   nenhum config quebrado é gravado. No modo rulesets o wizard informa
   quantas regras custom do WAF cada zona já usa.
2. **Sob demanda** (`test enforcer cloudflare`): re-executa as checagens de
   capacidade contra o config atual, incluindo existência da lista, contagem
   de itens e uso de regras por zona.
3. **Continuamente** (`doctor`): verifica que o token ainda resolve e é
   válido, que a lista ainda existe (com aviso de contagem de itens ao se
   aproximar do teto de 10k) e o uso de regras por zona — pegando listas
   apagadas por fora do EzyShield e tokens rotacionados ou expirados.

## Solução de Problemas

### Erros "Permission denied" ou "Insufficient permissions"

Verifique as permissões do seu token:

```bash
# Verifique o token com curl (substitua TOKEN pelo seu token real)
curl -H "Authorization: Bearer TOKEN" \
  https://api.cloudflare.com/client/v4/user/tokens/verify
```

Procure pelas permissões necessárias na resposta.

### Lista mostra "unauthorized" no Painel da Cloudflare

Isso é esperado se seu token de API tiver apenas Account Filter Lists:Edit (não Zone:Firewall:Edit). A lista existe e funciona; você apenas não consegue visualizá-la na interface do painel.

### Regras WAF não são criadas automaticamente

Verifique:
1. `zone_ids` está configurado em `config.yaml`
2. Seu token tem permissão `Zone → Firewall Services → Edit`
3. Execute `ezyshield doctor cloudflare` para verificar erros de permissão
4. Verifique os logs: `ezyshield status` → procure por entradas da Cloudflare

### "List at capacity" (10k items)

Se você atingir o limite de 10k items do plano gratuito, você tem duas opções:
1. Usar **modo Rulesets** (sem limite por rule, mas ~200 por rule)
2. Fazer upgrade para um plano pago da Cloudflare para limites maiores

## Configuração Multi-Conta

Agências e freelancers costumam gerenciar sites espalhados por contas
Cloudflare separadas, cada uma com seu próprio token de API. Um único daemon
EzyShield cuida de todas: cada ban é aplicado em todas as contas
configuradas, e uma falha em uma conta nunca bloqueia as demais.

Os wizards fazem essa configuração por você — tanto `ezyshield init` (etapa
de CDN) quanto `ezyshield config enforcer cloudflare` perguntam **"Add
another Cloudflare account?"** depois de cada conta. Cada conta recebe seu
próprio nome, modo (lists ou rulesets — misturar é normal), token validado e
sua própria variável no `.env` (`CLOUDFLARE_API_TOKEN` para uma única conta
sem nome, `CLOUDFLARE_API_TOKEN_<NOME>` para contas nomeadas). Rodar
`config enforcer cloudflare` de novo permite escolher uma conta existente
para reconfigurar ou adicionar outra.

A config resultante:

```yaml
enforce:
  cloudflare:
    # Conta 1
    - name: cliente_a
      api_token: env:CLOUDFLARE_API_TOKEN_CLIENTE_A
      mode: lists
      account_id: account_a_id
      zone_ids: [zone_a1, zone_a2]
    # Conta 2 — um modo diferente por conta é normal
    - name: cliente_b
      api_token: env:CLOUDFLARE_API_TOKEN_CLIENTE_B
      mode: rulesets
      zone_ids: [zone_b1]
```

Com mais de uma conta, cada entrada precisa de um `name` único (o wizard
garante isso, e se oferece para nomear uma entrada pré-existente sem nome).
Cada conta recebe gerenciamento independente de listas/regras e status
por conta em `test enforcer cloudflare` e `doctor`. Os logs mostram
`enforce/cloudflare[cliente_a]` e `enforce/cloudflare[cliente_b]` para clareza.

## Limitação de Taxa

EzyShield aplica um limite de 4 requisições/segundo nas chamadas de API da Cloudflare para manter-se bem abaixo dos limites da API pública. Isto é gerenciado automaticamente e não requer configuração.

## Considerações de Segurança

- Tokens de API são resolvidos no startup do daemon e nunca são registrados em logs
- Tokens não são incluídos em mensagens de erro ou logs
- Sempre use referências `env:VARNAME`; tokens inline no config são rejeitados no carregamento
- Restrinja as permissões do token e endereços IP nas configurações da Cloudflare quando possível
- O token account-level pode modificar suas Custom IP Lists — restrinja o acesso conforme necessário

## Validando sua Configuração

### Usando `test enforcer cloudflare`

Após configurar, valide seu setup com:

```bash
ezyshield test enforcer cloudflare --config-dir /etc/ezyshield/
```

Este comando irá:
- Verificar se o token de API é válido e ativo
- Verificar acesso à conta e zones
- Validar permissões da Cloudflare para seu token
- Relatar o que funciona e o que está faltando
- Fornecer sugestões claras de correção

**Exemplo de saída (modo lists com zone_ids):**

```
Cloudflare enforcer (mode: lists): pass
────────────────────────────────────
✓ Token validity: Token ID: abc...def, status: active
✓ Account access: Account ID: 0123456789abcdef
✓ List access (read): List "ezyshield_blocked" found (147 items, ID: lstxxxxx)
✓ Zone WAF access: Zone example.com (zone_id: aaa111) — WAF rule access OK
✗ Zone WAF access: Zone shop.example.org (zone_id: ccc333) — 403 Forbidden
  └─ Ensure token has Zone:Firewall Services:Edit on this zone

Result: 4/5 checks passed, 1 failed
```

**Código de saída**: 0 se todos os testes passarem, 1 se algum teste falhar

**Saída JSON**: Use a flag `--json` para saída estruturada apropriada para automação

## Veja Também

- ADR-0002: Estratégia de Bloqueio na Cloudflare (ver repositório ezy-shield `docs/internal/adr/`)
- [Documentação da API Cloudflare: Custom IP Lists](https://developers.cloudflare.com/api/operations/lists-list-lists)
- [Painel da Cloudflare](https://dash.cloudflare.com)
