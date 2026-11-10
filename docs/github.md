# Publicação no GitHub

## Crie o primeiro commit

Extraia `sentinela-aws.zip` e entre na pasta `sentinela-aws` que o ZIP criou. O conteúdo da pasta deve ser a raiz do repositório, com `README.md`, `infra/`, `src/` e `.github/` no primeiro nível. Versione os arquivos extraídos, incluindo `.github/workflows/ci.yml` e `infra/.terraform.lock.hcl`.

```bash
cd sentinela-aws
git init -b main
git add .
git status --short
git commit -m "feat: add Sentinela AWS incident response lab"
```

Confirme no status que o commit inclui código, Terraform, documentação e testes. Credenciais, estado, arquivos de variáveis reais e planos ficam no ambiente local. O exemplo `infra/lab.tfvars.example` é a referência pública.

## Envie o código

Crie no GitHub um repositório vazio chamado `sentinela-aws`. A visibilidade pública permite que recrutadores abram o portfólio. Como o projeto já inclui README, licença e `.gitignore`, deixe as opções de inicialização do GitHub desmarcadas.

```bash
git remote add origin https://github.com/SEU-USUARIO/sentinela-aws.git
git push -u origin main
```

Substitua `SEU-USUARIO` pelo seu login. Se preferir usar GitHub CLI, execute `gh auth login` e, após o commit, use `gh repo create sentinela-aws --public --source=. --remote=origin --push` como caminho completo para criar e enviar o projeto. [Publicação de código local](https://docs.github.com/en/repositories/creating-and-managing-repositories/adding-locally-hosted-code-to-github)

## Configure a página do portfólio

- Use a descrição `AWS S3 threat detection and automated incident response with Terraform, Python and GitHub Actions.`
- Adicione os tópicos `aws`, `cloud-security`, `incident-response`, `terraform`, `python` e `devsecops`.
- Abra **Actions → DevSecOps** e confira a execução no primeiro push. O workflow roda sem credenciais AWS.
- Fixe o repositório no perfil e use `make demo` para mostrar o antes e o depois do bloqueio de acesso público.
