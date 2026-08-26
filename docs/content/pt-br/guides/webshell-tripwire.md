---
title: Tripwire de Webshell
description: Detecte webshells jogados nos seus web roots — um tripwire, não um antivírus
order: 12
---

# Tripwire de Webshell

## O que é

Parsers de log enxergam as *requisições* que chegam ao servidor. Mas o
artefato de comprometimento mais valioso nunca aparece no access log: o
**arquivo** que o atacante colocou no seu web root — um `shell.php`
escrito por um formulário de upload, um plugin vulnerável ou uma
credencial de FTP roubada.

O tripwire de webshell vigia seus web roots por **arquivos novos ou
modificados com extensões web executáveis** e avisa no momento em que um
aparece.

Ele é **um tripwire, não um antivírus**:

- Detecta *mudança*, não malware. Um deploy legítimo também dispara
  (condensado em um único resumo — veja abaixo).
- A heurística de conteúdo é um indício, não um veredito. Arquivo marcado
  merece uma olhada; arquivo não marcado não está provado limpo.
- É **puramente observacional**. Um evento de filesystem não tem IP
  remoto, então nunca gera ban. Você recebe uma entrada no audit log, um
  evento no stream do `watch` e uma notificação — nada mais muda no
  sistema.

## Habilitando

Opt-in no `config.yaml`:

```yaml
webshell_watch:
  enabled: true
  roots:
    - /var/www/html
    - /srv/www/wordpress
  ignore:
    - cache            # substring: ignora qualquer caminho contendo "cache"
    - "*.bak.php"      # glob: padrão path.Match
  # extensions: [".php", ".phtml", ".php5", ".php7", ".phar"]  # padrão
  # interval_sec: 10   # cadência de varredura em segundos (mínimo 5)
```

`roots` exige caminhos absolutos e é obrigatório quando habilitado.
Roots típicos:

| Stack | Root |
|---|---|
| Apache ou nginx em Debian/Ubuntu | `/var/www/html` |
| WordPress (layouts comuns) | `/var/www/html`, `/srv/www/<site>` |
| Bind mounts do Docker | o lado do **host** do mount |

## Como detecta

O EzyShield varre os roots em um loop de polling limitado (padrão a cada
10s), comparando mtime e tamanho de cada arquivo vigiado com a varredura
anterior — a mesma abordagem baseada em stat usada no tailing de logs
(ADR-0004). A primeira varredura é uma baseline silenciosa; só mudanças
depois do startup geram eventos.

Polling significa que não há watch descriptors de inotify para esgotar,
nenhum limite de kernel para ajustar, e uma latência de detecção de no
máximo um intervalo de varredura — suficiente para um tripwire.

Em cada arquivo novo ou alterado, o EzyShield lê no máximo os primeiros
32 KB (somente leitura) e procura construções típicas de webshell —
`eval(`, `base64_decode`, `shell_exec`, `$_POST[`, `move_uploaded_file` e
similares. Uma ocorrência eleva a severidade da notificação para
**critical** ("possible webshell dropped"); caso contrário chega um
**warn** ("web-root change observed"). O conteúdo do arquivo é tratado
como dado hostil: apenas comparado byte a byte contra marcadores fixos,
nunca executado nem logado.

## Limites e comportamento em rajada

- Uma **mudança em massa** (deploy tocando mais de 20 arquivos em uma
  varredura) vira um único evento-resumo com a contagem de arquivos, em
  vez de uma tempestade de notificações. Se deploys são frequentes,
  adicione os diretórios-alvo ao `ignore`.
- No máximo 50.000 arquivos são rastreados por daemon; acima disso um
  aviso é logado uma vez e os excedentes não são vigiados.
- Caminhos registrados nos eventos são limitados a 256 bytes; nomes de
  arquivo hostis (caracteres de controle, escapes ANSI) são sanitizados
  na renderização como todo dado controlado por atacante.
- Remoções são silenciosas — apagar um arquivo não é sinal de drop (mas
  recriá-lo é).

## O que fazer quando disparar

1. Olhe o arquivo: `ls -la` no caminho da notificação, confira o uid do
   dono e o timestamp contra seu histórico de deploys.
2. Se você não o colocou lá, trate o host como comprometido no nível da
   aplicação web: tire o arquivo do web root (mova, não apague — é
   evidência), rotacione as credenciais que a aplicação guarda e procure
   o vetor de upload nos access logs em torno do mtime do arquivo.
3. Se foi deploy legítimo ou churn de cache, ajuste
   `webshell_watch.ignore` para o tripwire ficar quieto na rotina e
   barulhento nas surpresas.

## Fora de escopo (v1)

Quarentena/remoção automática, monitoramento de integridade em nível de
kernel, caminhos não-web e correlação do drop com a requisição HTTP que o
causou. O tripwire diz *que* aconteceu e *onde* — a investigação é sua.
