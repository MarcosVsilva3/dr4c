# DR4C

DR4C é uma ferramenta de linha de comando para reconhecimento de superfície de ataque. A versão 0.1.0 reúne descoberta passiva por Certificate Transparency, consultas DNS, verificações HTTP/HTTPS e uma opção de conexão TCP em portas autorizadas. Ela organiza observações; não procura nem confirma vulnerabilidades.

Use o DR4C somente em sistemas próprios ou com autorização explícita. Em programas de bug bounty, confirme no escopo quais domínios, subdomínios, caminhos e tipos de teste são permitidos.

## Requisitos

- Linux
- Python 3.12 ou mais recente
- Go 1.23 ou mais recente

O projeto usa a biblioteca padrão do Python. `scripts/go.sh` usa o Go instalado na máquina por padrão e mantém o cache em `.venv/go/`. Defina `DR4C_GO_TOOLCHAIN` (por exemplo, `go1.24.7` ou `auto`) para que o Go baixe e use outra versão compatível.

## Instalação

Na pasta do projeto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
dr4c doctor
dr4c --help
```

## Uso

Uma varredura combina a consulta ao crt.sh, descoberta DNS limitada, sondagens HTTP/HTTPS e caminhos comuns:

```bash
dr4c recon -d dominio-autorizado.example
```

O domínio informado define o escopo técnico daquela execução: o próprio domínio, seus subdomínios, endereços IP públicos e as portas HTTP/HTTPS padrão. Não é necessário criar um arquivo de escopo para esse uso.

`--active` desativa a consulta ao crt.sh e executa as verificações DNS e HTTP. `--passive` consulta o crt.sh e não faz essas verificações ativas:

```bash
dr4c recon -d dominio-autorizado.example --active
dr4c recon -d dominio-autorizado.example --passive
```

Os resultados aparecem no terminal e não são gravados por padrão. Para guardar um relatório JSON em `results/`, acrescente `--salve`:

```bash
dr4c recon -d dominio-autorizado.example --active --salve
```

O caminho padrão inclui o identificador da execução. Para escolher outro caminho, use `--output` junto com `--salve`. O DR4C não sobrescreve relatórios existentes.

## Verificação TCP opcional

As verificações TCP fazem apenas tentativas de conexão; não identificam serviços nem testam vulnerabilidades. Elas exigem um arquivo de escopo com autorização explícita. Copie e edite `scope.example.json`:

```json
{
  "authorized": true,
  "domains": ["dominio-autorizado.example"],
  "ip_ranges": [],
  "allowed_ports": [80, 443, 8080],
  "allow_private": false,
  "allow_port_scan": true
}
```

Depois execute:

```bash
dr4c recon -d dominio-autorizado.example \
  --scope-file ./scope.json --ports 80,443,8080
```

Cada porta solicitada precisa estar em `allowed_ports`. A ferramenta aceita até 32 portas e limita a varredura a 500 tentativas de conexão. Endereços privados exigem uma faixa correspondente em `ip_ranges` e `allow_private: true`.

## Limites e resultados

As sondagens HTTP usam GET, têm limite de tempo e leem no máximo 1 MiB por resposta por padrão. O orçamento total é de 500 requisições. O DR4C não autentica, não segue redirecionamentos HTTP e não baixa nem guarda o corpo completo das respostas. Respostas como HTTP 429 indicam que o alvo está limitando requisições; respeite as regras do programa e interrompa novas sondagens conforme necessário.

O relatório JSON contém nomes de hosts, endereços, caminhos, metadados HTTP e informações TLS. A pasta `results/` fica fora do Git para evitar que relatórios de alvos sejam enviados por engano.

## Desenvolvimento

```bash
make test
make build
```

Consulte [a referência do CLI](docs/CLI_REFERENCE.md), [a arquitetura](docs/ARCHITECTURE.md), [as notas de segurança](docs/SECURITY.md) e [as instruções de desenvolvimento](docs/DEVELOPMENT.md).

## Licença

Distribuído sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).
