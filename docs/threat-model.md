# Modelo de ameaças

## Escopo e ativos

O exercício protege a configuração de bloqueio público de um bucket S3 dedicado. A mesma conta regional fornece achados sobre possível exfiltração ou exclusão anômala. Os ativos operacionais são o bucket, as filas, o diário, as chaves, as roles de implantação e execução e a trilha de auditoria.

A role de execução confia no serviço Lambda. A fila aceita entregas do EventBridge das regras enumeradas. Identidades da própria conta com permissão de escrita nas filas ou de alteração das regras fazem parte da fronteira de administração. A validação do envelope restringe os alvos e efeitos, mas seu conteúdo por si só não autentica o emissor original.

## Cenários

| Ameaça ou falha | Controle | Risco residual |
| --- | --- | --- |
| Principal remove ou enfraquece o bloqueio do bucket | CloudTrail e reconciliação identificam o desvio. Em `enforce`, a função restaura e confere o estado. | A exposição depende também de políticas, ACLs e bloqueios superiores. Há uma janela entre alteração e correção. |
| Credencial faz operações S3 anômalas | GuardDuty S3 Protection seleciona sinais de exfiltração e exclusão. A resposta encaminha evidência para triagem. | A cobertura depende do detector, do plano habilitado e da detecção do GuardDuty. O worker não revoga credenciais. |
| Um evento tenta apontar para outro bucket | Conta, região, operação e alvo são verificados. O destino de escrita vem do ambiente, a API recebe o proprietário esperado e o IAM limita o ARN. | Administradores com acesso para alterar código, IAM ou infraestrutura podem redefinir as fronteiras. |
| Evento repetido, atrasado ou concorrente | Lease condicional por ID, releitura do S3, escrita idempotente, fases persistidas e filas de falhas. | IDs distintos podem gerar incidentes para um mesmo desvio. O SNS pode repetir uma notificação. |
| Falha no EventBridge, no SDK ou em uma integração | DLQs distintas, alarmes, logs, reentrega e reconciliação agendada para a configuração S3. | Perda de telemetria upstream ou desativação da stack pode reduzir a visibilidade. |
| Acesso excessivo à evidência | Recursos privados, criptografia em repouso, controles de entrega e logs com campos reduzidos. | Eventos brutos no CloudTrail e no SQS podem conter identidade e IP. DynamoDB permite alterações pelas identidades autorizadas. |

## Limites de operação

- O controle aplica-se a um bucket de uso geral, em uma conta e região. Alterações em bloqueios de conta, access points, políticas, objetos e credenciais ficam fora do escopo automático.
- A proteção de conta permanece como camada independente. A automação do laboratório altera exclusivamente a configuração no bucket dedicado.
- O S3 usa a ação IAM `s3:PutBucketPublicAccessBlock` para atualizar e excluir essa configuração. Em `enforce`, o código aplica os quatro valores fixos e o IAM restringe o bucket. [Permissões de bloqueio público](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- Terraform local retém estado e planos no ambiente do operador. O e-mail da assinatura, se configurado, é tratado como sensível no CLI, mas pode existir no estado.
- A política preventiva adequada depende das necessidades de compartilhamento de cada workload. Aqui a baseline foi definida para um bucket de laboratório que deve permanecer privado.
