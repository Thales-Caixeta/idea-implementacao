
# IDEA (International Data Encryption Algorithm)

Implementação limpa do IDEA em Python. Inclui:
- Cifragem/decifragem de **blocos** (64 bits)
- Geração de **subchaves** (52 palavras de 16 bits)
- **ECB** com padding (PKCS#7 de 8 bytes)

## Requisitos
- Python 3.10+

## Uso rápido
```bash
cd src
python idea.py
```

Saída esperada (exemplo):
```
PT: 0123456789ABCDEF
CT: <hex do cifrado>
RT: 0123456789ABCDEF
```

## API
- `expand_key(key16: bytes) -> list[int]`
- `encrypt_block(block8: bytes, subkeys: list[int]) -> bytes`
- `decrypt_block(block8: bytes, subkeys: list[int]) -> bytes`
- `ecb_encrypt(data: bytes, key16: bytes) -> bytes`
- `ecb_decrypt(data: bytes, key16: bytes) -> bytes`

## Observações
- A chave deve ter 16 bytes (128 bits).
- O bloco tem 8 bytes (64 bits).
- O modo ECB aqui é educativo.
