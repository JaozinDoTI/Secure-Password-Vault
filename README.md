# Secure Password Vault – Python

Um cofre de senhas simples, seguro e totalmente local, desenvolvido em Python para fins de estudo em criptografia, segurança ofensiva/defensiva e boas práticas de desenvolvimento seguro.

Este projeto demonstra:

- Derivação de chave forte (KDF)
- Criptografia autenticada (AES-GCM ou ChaCha20-Poly1305)
- Armazenamento seguro usando salt + nonce + ciphertext
- Manipulação de um cofre criptografado via linha de comando

---

## Como funciona

O cofre utiliza **criptografia autenticada** e **derivação de chave** para garantir segurança real.  
A senha mestra **nunca é armazenada**, e a chave criptográfica é gerada a partir dela usando:

### Derivação de chave (KDF)
- Salt aleatório
- PBKDF2 / Scrypt / Argon2 (dependendo da versão)
- Milhares de iterações para defesa contra brute-force

### Criptografia autenticada
- AES-256-GCM **ou** ChaCha20-Poly1305
- Garante confidencialidade + integridade + autenticação

### Estrutura interna do cofre

```json
{
  "salt": "...",
  "nonce": "...",
  "ciphertext": "..."
}
