# Implantação e exercício na AWS

Execute os comandos na raiz do projeto, com AWS CLI v2, Python 3.12, Terraform 1.17.x e uma identidade autorizada na conta sandbox. Os exemplos usam Bash e a região `us-east-1`. Escolha o perfil AWS que você já configurou para o laboratório.

## 1. Confira a conta e os detectores

```bash
export AWS_PROFILE=sentinela-lab
export AWS_REGION=us-east-1
aws sts get-caller-identity
aws cloudtrail describe-trails --include-shadow-trails
aws guardduty list-detectors
cp infra/lab.tfvars.example infra/lab.tfvars
```

Se reutilizar uma trilha, confirme que ela está registrando escritas de gerenciamento do S3 na região e configure `create_cloudtrail = false`. Para uma trilha criada pela stack, o bucket de auditoria e a chave KMS também serão provisionados. Duplicar uma trilha que já entrega esses eventos pode gerar cobrança.

Em uma região sem detector, habilite `create_guardduty_detector = true` somente se a stack deve assumir o detector da conta sandbox. A AWS pode ativar planos opcionais ao criar um detector. Revise os planos e a cobrança do laboratório no console. Para um detector existente, mantenha `false` e verifique S3 Protection no console do GuardDuty. [Criação do detector](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateDetector.html) · [Configuração do S3 Protection](https://docs.aws.amazon.com/guardduty/latest/ug/data-source-configure.html)

Caso queira alertas por e-mail, preencha `alert_email` no arquivo local e confirme a assinatura que o SNS enviar. Esse endereço pode aparecer no estado. As configurações locais, os planos e o estado ficam fora do Git.

## 2. Aplique em modo de observação

```bash
terraform -chdir=infra init -lockfile=readonly
terraform -chdir=infra plan -var-file=lab.tfvars -out=observe.tfplan
terraform -chdir=infra apply observe.tfplan
terraform -chdir=infra output
```

Confira os outputs e a proteção inicial. Se a stack criou a trilha, valide também `IsLogging`.

```bash
BUCKET=$(terraform -chdir=infra output -raw lab_bucket)
ACCOUNT=$(terraform -chdir=infra output -raw account_id)

aws s3api get-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT"
aws s3control get-public-access-block --account-id "$ACCOUNT"

# Apenas quando a trilha é gerenciada pela stack.
TRAIL=$(terraform -chdir=infra output -raw cloudtrail_name)
aws cloudtrail get-trail-status --name "$TRAIL" --query IsLogging
```

O estado é local por padrão. Em uso compartilhado, configure antes do primeiro `init` um backend S3 já provisionado e separado da stack, com versionamento, criptografia, bloqueio público e `use_lockfile = true`. [Backend S3 do Terraform](https://developer.hashicorp.com/terraform/language/backend/s3)

## 3. Teste a triagem do GuardDuty

Com o detector e o plano S3 Protection ativos, use um achado de exemplo. Substitua o valor de `DETECTOR_ID` pelo ID exibido na etapa 1 ou no output `guardduty_detector_id`. A geração de um achado de exemplo usa um recurso fictício.

```bash
DETECTOR_ID="substitua-pelo-id-do-detector"
aws guardduty create-sample-findings --detector-id "$DETECTOR_ID" \
  --finding-types 'Exfiltration:S3/AnomalousBehavior'
```

Procure `triage_required` no diário e no tópico SNS. Em casos de atualização de um achado já existente, a frequência de publicação do detector pode afetar o prazo. [Achados de exemplo do GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html)

## 4. Teste a remediação

Edite `infra/lab.tfvars` para `response_mode = "enforce"` e aplique o plano revisado.

```bash
terraform -chdir=infra plan -var-file=lab.tfvars -out=enforce.tfplan
terraform -chdir=infra apply enforce.tfplan
PYTHONPATH=src:. python3 scripts/cloud_drill.py --confirm-sandbox
```

O script aborta antes de escrever se o perfil AWS divergir do estado, o bloqueio público da conta estiver incompleto ou o bucket tiver dados, versões, política pública ou propriedade incompatível. No bucket vazio, o script muda somente `BlockPublicPolicy` para `false`. As outras três opções do bucket e as quatro opções da conta ficam ativas.

A execução só termina com sucesso ao observar as quatro opções restauradas no S3 e um registro concluído no DynamoDB com a alteração esperada. O JSON mostra a origem `cloudtrail` ou `reconciliation`. Para confirmar a via por evento, verifique que a origem foi `cloudtrail`. Se a evidência não aparecer no prazo, o script tenta restaurar e verificar a baseline. [Ação manual de recuperação](runbook.md#contenção-manual)

## 5. Inspecione os resultados

```bash
TABLE=$(terraform -chdir=infra output -raw incident_table)
LOGS=$(terraform -chdir=infra output -raw worker_log_group)

aws dynamodb scan --table-name "$TABLE" --limit 20 \
  --query 'Items[].{id:incident_id.S,phase:phase.S,result:evidence.M.outcome.S}'
aws logs tail "$LOGS" --since 30m --format short
terraform -chdir=infra output -json queue_urls
```

Na página de alarmes do CloudWatch, confira os três alarmes do projeto. Com assinatura confirmada e um alarme em `OK`, é possível verificar a entrega de uma notificação de alarme com uma mudança temporária de estado.

```bash
aws cloudwatch set-alarm-state --alarm-name sentinela-aws-delivery-dlq \
  --state-value ALARM --state-reason "Exercício de entrega SNS do laboratório"
```

## 6. Remova o laboratório

1. Exporte os registros ou logs que você precisa conservar e confirme que a chave que cifra essas cópias permanecerá disponível.
2. Se a stack criou CloudTrail, pare a trilha com `aws cloudtrail stop-logging --name "$TRAIL"`. Confirme que é a trilha da stack e aguarde entregas em trânsito.
3. Os buckets foram configurados com `force_destroy = false`. Para remover a stack, esvazie pelo console S3 apenas os buckets da stack que você autorizou apagar. O esvaziamento remove versões e marcadores. Se houver entregas tardias da trilha, confira o bucket novamente.
4. Revise o plano de remoção e aplique. Detectores e trilhas reutilizados ficam fora da stack.

```bash
terraform -chdir=infra plan -destroy -var-file=lab.tfvars -out=destroy.tfplan
terraform -chdir=infra apply destroy.tfplan
```

A remoção agenda a chave KMS criada pela stack para exclusão. Proteja qualquer evidência que ainda dependa dela antes do destroy. Recursos do laboratório podem gerar cobrança por uso e retenção, inclusive GuardDuty, CloudTrail, KMS e armazenamento. [Calculadora de preços da AWS](https://calculator.aws/)
