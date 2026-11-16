# Segurança e uso responsável

Execute o DR4C somente em sistemas próprios ou com autorização explícita. Em bug bounties, confira o escopo e os limites de requisição antes de iniciar. O domínio informado delimita a execução padrão, mas a ferramenta não consulta nem confirma as regras de cada programa.

O pipeline faz requisições HTTP GET com timeout e limite de leitura de resposta. Não envia credenciais, não autentica, não segue redirecionamentos e não tenta explorar vulnerabilidades. A verificação opcional de portas só abre conexões TCP e exige autorização explícita no arquivo de escopo.

O escopo valida os destinos e bloqueia endereços privados, loopback, link-local, multicast e não especificados, salvo quando uma faixa privada foi autorizada para um ambiente de laboratório. O motor HTTP conecta aos endereços validados e mantém o hostname para HTTP e TLS.

## Dados produzidos

O resultado inclui domínios e subdomínios, endereços IP, caminhos consultados, status HTTP, títulos, fingerprints, alguns metadados de resposta e informações do certificado TLS. O corpo integral das respostas não é salvo. Por padrão, os resultados ficam apenas na tela; `--salve` cria um JSON em `results/`.

Relatórios ainda podem revelar nomes de alvos, rotas e endereços. Revise-os antes de compartilhar. A pasta `results/` está excluída do Git para reduzir o risco de publicar relatórios por engano.

O DR4C não tem limitador adaptativo para respostas HTTP 429. Se o alvo limitar as requisições, respeite a política aplicável e interrompa ou reduza a atividade conforme autorizado. Um status HTTP ou uma classificação do DR4C, por si só, não confirma uma vulnerabilidade.
