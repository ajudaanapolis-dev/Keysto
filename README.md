# keystone-btc-proof

Biblioteca Rust e CLI de referência para verificar `ClaimBundle`s do Keystone alpha.

## O que o projeto faz

O verificador recebe:

- uma ordem (`Order`)
- uma transação Bitcoin bruta (`raw_tx`)
- uma prova de inclusão de Merkle
- uma cadeia de headers ancorada em checkpoints confiáveis
- um contexto L2 com o tempo atual

Ele então:

1. parseia a transação e recomputa `txid_internal`
2. valida parâmetros e janela temporal da ordem
3. verifica checkpoint, PoW e linkagem dos headers
4. verifica profundidade e altura máxima de inclusão
5. verifica a Merkle proof
6. rederiva o `scriptPubKey` esperado da ordem
7. retorna um `Settlement` se tudo estiver válido

## CLI

O projeto expõe um binário com dois comandos:

```bash
target/release/keystone-btc-proof template
target/release/keystone-btc-proof verify request.json
cat request.json | target/release/keystone-btc-proof verify -
target/release/keystone-btc-proof serve 0.0.0.0:8080
```

## Build local

Este ambiente não tem toolchain/linker do sistema prontos no `PATH`, então o repositório inclui wrappers para compilar:

```bash
./cargo.sh test
./cargo.sh build --release
./cargo.sh run -- template
./cargo.sh run -- verify sample-request.json
./cargo.sh run -- serve 0.0.0.0:8080
```

O wrapper usa:

- Rust em `/root/snap/codex/34/.cargo/bin`
- `tools/zigcc` se existir
- caso contrário, `cc` ou `clang` do sistema

### `template`

Gera um payload JSON válido e autoconsistente para teste:

```bash
./cargo.sh run -- template > sample-request.json
```

### `verify`

Lê um JSON com este formato:

```json
{
  "claim_bundle": { "...": "..." },
  "keys": [
    {
      "key_id": "hex32",
      "xpub": {
        "public_key": "hex33",
        "chain_code": "hex32"
      }
    }
  ],
  "checkpoints": [
    {
      "checkpoint_id": "hex32",
      "record": {
        "network": "regtest",
        "height": 100,
        "hash": "hex32",
        "nbits": 545259519
      }
    }
  ],
  "l2_context": {
    "now_l2": 15
  }
}
```

Campos binários usam hex, com ou sem prefixo `0x`.

### `serve`

Sobe uma interface web simples e responsiva para testar pelo navegador:

```bash
./cargo.sh run -- serve 0.0.0.0:8080
```

Depois abra no celular:

```text
http://IP_DA_VPS:8080
```

Rotas disponíveis:

- `GET /` interface HTML
- `GET /api/sample` payload JSON de exemplo
- `POST /api/verify` verificação do bundle

## Frontend estático para GitHub Pages

O repositório agora inclui uma versão estática em [`docs/index.html`](./docs/index.html).

Ela foi feita para ser publicada no GitHub Pages e conversar com a API da VPS via `fetch`.
O backend já responde com CORS aberto para:

- `GET /api/sample`
- `POST /api/verify`
- `OPTIONS /api/verify`

Se este repositório for enviado para o GitHub, o workflow em [`.github/workflows/pages.yml`](./.github/workflows/pages.yml) publica automaticamente o conteúdo de `docs/` no GitHub Pages.

O link final terá este formato:

```text
https://SEU_USUARIO.github.io/NOME_DO_REPO/
```

## Observações

- O modelo de headers ainda é `alpha`: usa checkpoints confiáveis e `nBits` fixo do checkpoint.
- A codificação canônica de `OrderPreimage` ainda precisa ser confirmada contra a especificação externa do protocolo.
- O projeto hoje é adequado como verificador de referência e ferramenta de laboratório. Não deve ser tratado como consenso de produção sem validar essas premissas.
