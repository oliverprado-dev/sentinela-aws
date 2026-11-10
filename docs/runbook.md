# Runbook de incidentes

## Triagem inicial

1. Abra a notificação e copie `incident_id`. Consulte o item no DynamoDB e os logs estruturados do Lambda no mesmo intervalo.
2. Registre a origem, operação, conta, região e horários. Na trilha ou no histórico CloudTrail, use `signal.event_id` para buscar o autor da alteração. Preserve a referência ao evento bruto em um local de acesso restrito.
3. Para sinais do GuardDuty, abra o achado pelo `signal.finding_id`. Confira a identidade, operações observadas, buckets, período e volume quando disponível. Correlacione com a telemetria autorizada e escale ao responsável por credenciais ou pelo bucket.
4. Para desvio de bloqueio público, confronte a evidência `before` e `after` com uma nova leitura do S3. Revise o bloqueio da conta e políticas ou ACLs relevantes no intervalo. A volta à baseline encerra a correção de configuração. A investigação de eventual exposição segue separadamente.

```bash
TABLE=$(terraform -chdir=infra output -raw incident_table)
INCIDENT='cloudtrail#substitua-pelo-event-id'
aws dynamodb get-item --table-name "$TABLE" --consistent-read \
  --key "{\"incident_id\":{\"S\":\"$INCIDENT\"}}"
```

## Falhas de entrega ou processamento

| Alarme | Primeira ação | Recuperação |
| --- | --- | --- |
| `queue-backlog` | Verifique throttling e logs do worker, o mapeamento do SQS e a idade das mensagens. | Corrija a dependência ou permissão antes de aumentar concorrência. |
| `delivery-dlq` | Leia os atributos da mensagem, como `RULE_ARN`, `TARGET_ARN` e `ERROR_CODE`. Confira a política da fila e o alvo. | Após a correção, reenvie o corpo original de uma mensagem revisada para a fila principal e confirme o resultado antes de remover a cópia. |
| `processing-dlq` | Consulte o log por ID SQS, a fase do incidente e o serviço com falha. Separe payload inválido de falha transitória. | Após corrigir a causa, use o redrive da fila de processamento para a fila principal, com taxa inicial baixa. Preserve e investigue mensagens inválidas. |

Use o comando de leitura apenas no ambiente autorizado. A visualização torna a mensagem temporariamente invisível para outros leitores.

```bash
URL=$(terraform -chdir=infra output -json queue_urls | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["delivery"])')
aws sqs receive-message --queue-url "$URL" --max-number-of-messages 1 \
  --message-attribute-names All --message-system-attribute-names All
```

Ao reprocessar, preserve o ID de origem no corpo. O ID de mensagem do SQS pode mudar. Verifique a fase `done` pelo ID do incidente e acompanhe possíveis duplicatas do SNS. [Atributos da DLQ de entrega](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)

Se houver falhas de entrega e a DLQ estiver vazia, consulte `InvocationsFailedToBeSentToDlq` no EventBridge e verifique a política da fila e da chave KMS. O operador de redrive precisa de acesso ao KMS da origem e do destino. [Permissões de redrive](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html)

## Contenção manual

Se precisar desarmar a resposta, aplique `response_mode = "observe"` com Terraform. Isso retira a permissão corretiva da role do worker. Uma invocação em curso e a propagação do IAM podem afetar a transição. Confira a configuração efetiva e os incidentes em andamento.

Use uma identidade autorizada para restaurar o bloqueio no bucket sandbox.

```bash
BUCKET=$(terraform -chdir=infra output -raw lab_bucket)
ACCOUNT=$(terraform -chdir=infra output -raw account_id)
aws s3api put-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
aws s3api get-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT"
```

Confira as quatro opções em `true`. Anote quem fez a alteração e o horário. Preserve as evidências antes de encerrar a investigação.

## Registro de encerramento

| Campo | Evidência esperada |
| --- | --- |
| Referências | ID do incidente, evento CloudTrail ou achado GuardDuty. |
| Linha do tempo | Detecção, primeira leitura, tentativa corretiva, verificação e notificação, quando aplicáveis. |
| Escopo | Conta, região e recurso confirmado. |
| Impacto | Exposição observada, investigada ou indeterminada, com fontes de verificação. |
| Encerramento | Estado atual do recurso, validação do operador e referência para acompanhamento. |
