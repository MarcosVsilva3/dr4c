# Arquitetura

O Python valida o escopo, coordena descoberta e sondagens e monta os resultados. O motor HTTP em Go recebe pedidos JSON Lines e devolve metadados das respostas. O CLI mostra o relatório na tela e só cria um arquivo JSON quando recebe `--salve`.

## Escopo e conexões

1. `recon -d` cria um escopo temporário para o domínio, seus subdomínios, endereços públicos e portas 80/443. Um arquivo de escopo pode acrescentar limites e autorizações para verificações TCP.
2. Antes de uma requisição, o Python valida o domínio, a porta e os endereços resolvidos. Endereços privados, loopback, link-local, multicast e não especificados são recusados, exceto quando uma faixa privada foi autorizada explicitamente para uso de laboratório.
3. O Python passa os IPs validados ao motor Go. O motor conecta a esses endereços mantendo o hostname original para o cabeçalho HTTP e a validação TLS.
4. O fluxo usado pelo pipeline não segue redirecionamentos; registra o status e o cabeçalho `Location` sem pedir o destino.

Essa validação reduz o risco de uma mudança de DNS entre a checagem e a conexão. O escopo aceita domínios exatos e seus subdomínios, faixas IP explícitas e portas permitidas. Não há configuração de exclusões por host ou caminho.

## Etapas da execução

- **Descoberta passiva:** consulta o crt.sh e mantém a origem dos subdomínios encontrados.
- **Limite de hosts:** inventário limitado a 50 hosts por execução.
- **DNS:** usa o resolvedor do sistema para endereços A/AAAA e compara dois nomes aleatórios para estimar wildcard DNS.
- **HTTP/HTTPS:** verifica caminhos de `wordlists/common-paths.txt` com concorrência limitada. Um caminho aleatório serve de referência para classificar respostas parecidas com páginas genéricas ou soft 404. O orçamento padrão é de 500 requisições.
- **TCP opcional:** faz conexões às portas autorizadas, com limite de 500 tentativas.
- **Saída:** exibe os ativos, DNS, portas e respostas HTTP/HTTPS no terminal. `--salve` grava o mesmo resultado em um JSON.

As classificações de resposta são observações heurísticas, não achados confirmados de segurança.

## O que ainda não faz

O DR4C não consulta registros MX/NS, não rastreia links, não tem limitador adaptativo para HTTP 429, não enumera protocolos TLS e não testa vulnerabilidades. Também não guarda o corpo integral das respostas nem mantém histórico automaticamente.
