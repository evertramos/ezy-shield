---
title: Referência de CLI
description: Todos os comandos e flags
order: 4
---

# Referência de CLI

[Conteúdo de tradução em andamento - veja docs/content/en/reference/cli.md para a versão em inglês]

Referência completa para a CLI do `ezyshield`.

## ezyshield config

Inspecionar e validar a configuração.

### ezyshield config show

Renderiza a configuração efetiva — após parsing, validação estrita e defaults — em YAML, ou JSON com `--json`. Valores de segredos nunca aparecem na saída: campos de credencial guardam referências `env:VARNAME` por design, e valores de headers de webhook (que podem conter tokens crus) são exibidos como `<redacted>`.

```bash
ezyshield config show

# Saída em JSON
ezyshield config show --json

# Arquivos em locais não padrão
ezyshield config show --config ./config.yaml --policy ./policy.yaml
```

Códigos de saída: `0` renderizado, `1` configuração inválida, `2` arquivo não encontrado / ilegível.

### ezyshield config validate

Valida `config.yaml` e `policy.yaml` sem iniciar o daemon: parsing YAML estrito, restrições de campos, monotonicidade da tabela de strikes, CIDRs da allowlist e avisos para caminhos de log ilegíveis ou variáveis de ambiente não definidas.

```bash
ezyshield config validate

# Arquivos em locais não padrão
ezyshield config validate --config ./config.yaml --policy ./policy.yaml
```

O comando de nível superior `ezyshield validate` é mantido como alias e se comporta de forma idêntica.

Códigos de saída: `0` válido (pode ter avisos), `1` erros encontrados, `2` arquivo não encontrado / ilegível.

### ezyshield config enforcer <name>

Wizard interativo para adicionar ou reconfigurar um enforcer em uma instalação existente — os mesmos prompts e a mesma validação seca de token do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config enforcer cloudflare
```

- A escrita é atômica (arquivo temporário + rename); o arquivo anterior é mantido como `config.yaml.bak` e a configuração mesclada é revalidada antes de qualquer coisa tocar o disco. Comentários não são preservados — recupere-os do `.bak` se necessário.
- Tokens secretos vão para o arquivo `.env` ao lado do `config.yaml` (modo 0600), nunca para o `config.yaml` em si (`api_token: env:CLOUDFLARE_API_TOKEN`).
- Em caso de sucesso, o comando imprime as chaves alteradas e os próximos passos (`config validate`, reiniciar o daemon). Se o wizard for abortado, nada é escrito.

Nomes disponíveis: `cloudflare`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config notifier <name>

Wizard interativo para adicionar, reconfigurar ou remover um canal de notificação em uma instalação existente.

```bash
sudo ezyshield config notifier telegram
sudo ezyshield config notifier email
sudo ezyshield config notifier slack
sudo ezyshield config notifier discord
sudo ezyshield config notifier webhook
```

- Cada canal pergunta suas próprias configurações (telegram: chat IDs; email: from/to/host SMTP/porta/TLS/usuário; slack: override opcional de canal; webhook: header de autenticação opcional) mais um filtro de severidade (`info,warn,critical`; vazio = todas).
- Valores de credencial — tokens de bot, URLs de webhook (capability URLs são segredos), senhas SMTP, valores de headers de autenticação — são lidos com entrada oculta e oferecidos de duas formas: colar o valor (armazenado no arquivo `.env` ao lado do `config.yaml`, modo 0600, mesclado sem tocar nas outras linhas) ou referenciar uma variável de ambiente que você já gerencia (ex.: via sops/vault) — nesse caso o wizard grava `env:SUA_VAR` e nunca toca o `.env`. Segredos nunca vão para o `config.yaml`; ele carrega apenas referências como `bot_token: env:TELEGRAM_BOT_TOKEN`.
- Pressionar ENTER no prompt de colagem é aceitável: um valor existente no `.env` é mantido como está; caso contrário, um placeholder é gravado para você preencher depois.
- No canal genérico `webhook`, o valor do header de autenticação também é segredo: o `config.yaml` recebe `Authorization: env:WEBHOOK_AUTH_HEADER` e o daemon resolve a referência na inicialização. Valores de header simples (sem `env:`) em configs escritas à mão continuam funcionando sem mudanças.
- Reconfigurar substitui a entrada daquele canal; os ajustes compartilhados (`rate_limit_per_minute`, `dedup_window_sec`) e os outros canais são preservados. Para desabilitar um canal, responda `n` no prompt de configuração: o wizard então oferece remover a entrada existente (default não). Recusar deixa o arquivo intocado.
- A semântica de escrita é a mesma dos outros wizards: escrita atômica, `config.yaml.bak`, revalidação antes de salvar e resumo das chaves alteradas em caso de sucesso. Verifique a entrega depois com o comando de teste de notificação mostrado nos próximos passos.

Nomes disponíveis: `telegram`, `email`, `slack`, `discord`, `webhook`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config ai <provider>

Wizard interativo para configurar (ou trocar) o provedor de IA em uma instalação existente — os mesmos prompts de modelo e chave de API do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config ai anthropic
sudo ezyshield config ai openai
sudo ezyshield config ai ollama
```

- A chave de API é lida com entrada oculta e oferecida de duas formas: colar a chave (armazenada no arquivo `.env` ao lado do `config.yaml`, modo 0600, mesclada sem tocar nas outras linhas) ou referenciar uma variável de ambiente que você já gerencia (ex.: via sops/vault) — nesse caso o wizard grava `api_key: env:SUA_VAR` e nunca toca o `.env`. Chaves nunca vão para o `config.yaml`.
- Pressionar ENTER no prompt de colagem é aceitável: uma chave existente no `.env` é mantida como está; caso contrário, um placeholder é gravado para você preencher depois. `ollama` roda localmente e não tem chave.
- Reconfigurar substitui os campos do provedor (`provider`, `model`, `api_key`) mas preserva seus ajustes (`ambiguous_band`, `token_budget_daily`). A semântica de escrita é a mesma do `config enforcer`: escrita atômica, `config.yaml.bak`, revalidação antes de salvar.

Provedores disponíveis: `anthropic`, `openai`, `ollama`.

Códigos de saída: `0` salvo, `1` falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config collector <name>

Wizard interativo para adicionar, reconfigurar ou remover um coletor de logs em uma instalação existente — os mesmos prompts que o wizard de init executa para aquela fonte, sem regenerar mais nada.

```bash
sudo ezyshield config collector sshd
sudo ezyshield config collector nginx
sudo ezyshield config collector apache
```

- `sshd` gerencia o coletor journald (confirmação e, opcionalmente, troca da unidade systemd). Nomes de servidores web (`nginx`, `apache`, `traefik`, `caddy`) perguntam primeiro a fonte de log: `file` (caminho do access-log no host, com default sugerido por servidor) ou `docker` (nome do container, lendo o stdout dele).
- Reconfigurar substitui a entrada existente daquela fonte (identificada pelo parser nos servidores web e pela unidade SSH no `sshd`) — o wizard nunca acrescenta duplicatas. Configurações com várias fontes para o mesmo servidor (ex.: dois logs de vhost do nginx) são editadas diretamente no `config.yaml`.
- Para desabilitar uma fonte, responda `n` no prompt de configuração: o wizard então oferece remover a entrada existente (default não). Recusar deixa o arquivo intocado.
- Coletores não carregam segredos; tudo fica no `config.yaml`. A semântica de escrita é a mesma dos outros wizards: escrita atômica, `config.yaml.bak`, revalidação antes de salvar e resumo das chaves alteradas em caso de sucesso.

Nomes disponíveis: `sshd`, `nginx`, `apache`, `traefik`, `caddy`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

## ezyshield test

Executa testes de conectividade contra os componentes configurados. Como o `config`, o grupo segue o padrão `<kind> <name>`, então tipos de componente futuros se encaixam nos mesmos verbos.

### ezyshield test enforcer <name>

Testa a configuração e as permissões de um backend de enforcement: validade do token, acesso à conta/zones e as permissões exatas de API que o enforcer precisa — com sugestão de correção para cada verificação que falhar.

```bash
sudo ezyshield test enforcer cloudflare

# Testar todos os backends de enforcement configurados
sudo ezyshield test enforcer all
```

Nomes disponíveis: `all`, `cloudflare`, `nftables`.

Código de saída `0` se todas as verificações passarem, diferente de zero se alguma falhar.

### ezyshield test notifier <name>

Envia um alerta sintético para verificar um canal de notificação de ponta a ponta (segredos resolvidos do ambiente, mensagem realmente entregue).

```bash
sudo ezyshield test notifier telegram

# Testar todos os canais configurados
sudo ezyshield test notifier all
```

Nomes disponíveis: `all`, `email`, `telegram`.

Código de saída diferente de zero em caso de falha.

### Aliases descontinuados

Os verbos pré-1.0 `test-enforce <name>` e `test-notify <name>` continuam funcionando como aliases ocultos de `test enforcer` / `test notifier` — mesmas flags, mesmo comportamento — e imprimem um aviso de migração de uma linha no stderr. Serão removidos na 1.0.

[Traduções a seguir...]
