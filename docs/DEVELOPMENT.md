# Desenvolvimento

Crie o ambiente e instale o projeto em modo editável:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Rode a suíte Python e Go com:

```bash
make test
```

Para compilar o motor HTTP:

```bash
make build
```

O script `scripts/go.sh` seleciona o toolchain Go e guarda os caches dentro de `.venv/go/`. Relatórios gerados com `--salve` ficam em `results/`; esse diretório não deve ser enviado ao GitHub.
