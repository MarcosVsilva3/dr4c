# Referência do CLI

```text
dr4c --help
dr4c --version
dr4c doctor
dr4c config
dr4c recon -d DOMÍNIO [--scope-file ARQUIVO] [--passive | --active]
  [--config ARQUIVO] [--timeout SEGUNDOS] [--threads QUANTIDADE]
  [--ports PORTA[,PORTA...]] [--salve] [--output ARQUIVO_JSON]
```

## Reconhecimento

O domínio passado com `-d` define o escopo técnico padrão daquela execução: o domínio e seus subdomínios, endereços públicos e portas 80/443. Use a ferramenta apenas em alvos autorizados.

Sem opção de modo, o DR4C consulta o crt.sh e executa as verificações DNS e HTTP/HTTPS. `--active` pula o crt.sh; `--passive` faz somente a consulta passiva.

Os resultados são exibidos no terminal. Para salvar um único relatório JSON em `results/`, use `--salve`. `--output ARQUIVO_JSON` escolhe outro caminho e só pode ser usado com `--salve`. Arquivos existentes não são sobrescritos. O CLI não grava resultados em SQLite.

## Portas TCP

`--ports` faz verificações de conexão TCP, sem identificação de serviço ou teste de vulnerabilidade. A opção exige `--scope-file`, `authorized: true`, `allow_port_scan: true` e que cada porta esteja listada em `allowed_ports`. São aceitas até 32 portas e no máximo 500 tentativas por execução.

## Configuração

`configs/default.yaml` define o timeout HTTP, a concorrência, o limite de bytes por resposta e o orçamento total de requisições. Os valores podem ser substituídos com `--timeout` e `--threads`, ou por um arquivo indicado com `--config`. O orçamento HTTP padrão é 500. As consultas DNS usam o resolvedor configurado no sistema e não têm timeout configurável nesta versão.
