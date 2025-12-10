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

Sem a senha mestra correta, o conteúdo é totalmente inacessível.

Exemplo real:

{
  "salt": "cZlfPX1hTYNJclogX/oaXQ==",
  "nonce": "vyeEuUT77WWGLdnc",
  "ciphertext": "YhBa/wUrlQI5PlbuylA/XR4TW41ddQbjMD8Lh3cQaROuUZj5vjYyNIp/nwLEIbyFQMGZ+otcDPY5BIv1LzJiU0SeLNXYAGd8VbQl/BMxo95F2HdHRqFSAVBgbw=="
}

🛠️ Instalação
Requisitos

Python 3.10+

Biblioteca cryptography

Instalar dependências
pip install cryptography

🚀 Como usar

O script principal é:

vault_secure.py

➤ Criar um cofre novo
python vault_secure.py init meucofre.bin


Você será solicitado a definir a senha mestra.

➤ Adicionar uma credencial
python vault_secure.py add meucofre.bin github joaousuario MinhaSenha123

➤ Listar serviços armazenados
python vault_secure.py list meucofre.bin

➤ Obter as credenciais de um serviço
python vault_secure.py get meucofre.bin github

📐 Arquitetura do Projeto
SecurePasswordVault/
│
├── vault_secure.py        # Script principal e CLI
├── crypto_engine.py       # KDF, criptografia e descriptografia
├── storage_handler.py     # Manipulação do arquivo criptografado
├── README.md              # Documentação do projeto
├── .gitignore             # Ignorar arquivos sensíveis e temporários
└── LICENSE                # Licença MIT


Cada módulo é isolado para facilitar aprendizado e manutenção.

🛡️ Segurança Implementada

✔ Salt aleatório
✔ Nonce único por operação
✔ Criptografia autenticada (GCM/Poly1305)
✔ Derivação de chave robusta
✔ Nenhuma senha armazenada em texto claro
✔ Arquivo do cofre totalmente ilegível
✔ Sem dependências externas ou servidores

❗ Importante

Este projeto é exclusivamente educacional.
Para uso real, recomenda-se adicionar:

Limite de tentativas

Argon2id como KDF padrão

Anti‑tampering (HMAC adicional)

Verificação de integridade do arquivo

Hardening do sistema

Integração com hardware keys (ex: YubiKey)

Auditoria e logging seguro

🎯 Objetivo deste projeto

Este projeto foi criado com foco em:

Aprender criptografia moderna na prática

Criar uma aplicação real e segura

Desenvolver boas práticas de segurança

Demonstrar domínio técnico em portfólio

Evoluir habilidades para atuar em Red Team / Segurança Ofensiva

📄 Licença

Este projeto está sob a licença MIT.
Você pode usar, modificar e estudar como quiser.

💬 Autor

Projeto pessoal desenvolvido por João Henrique
Focado em estudos de Python, Segurança da Informação e Red Team.
