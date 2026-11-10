"""Exercise S3 remediation against a deployed, empty Sentinela AWS lab."""

import argparse
import json
import subprocess
import sys
import time

from sentinela.model import BASELINE

DRIFT = {**BASELINE, "BlockPublicPolicy": False}


def command_json(args):
    completed = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, timeout=45)
    return json.loads(completed.stdout) if completed.stdout.strip() else {}


def aws_cli(region):
    def aws(*args):
        return command_json(
            ["aws", "--no-cli-pager", "--region", region, "--output", "json", *args]
        )

    return aws


def check_preconditions(aws, outputs):
    account = outputs["account_id"]["value"]
    if outputs["response_mode"]["value"] != "enforce":
        raise RuntimeError("Implante o laboratório em modo enforce.")
    if aws("sts", "get-caller-identity")["Account"] != account:
        raise RuntimeError("O perfil AWS e o estado Terraform pertencem a contas diferentes.")

    account_flags = aws("s3control", "get-public-access-block", "--account-id", account)
    if account_flags["PublicAccessBlockConfiguration"] != BASELINE:
        raise RuntimeError("As quatro opções de bloqueio da conta precisam estar ativas.")

    bucket = outputs["lab_bucket"]["value"]
    target = ("--bucket", bucket, "--expected-bucket-owner", account)
    versions = aws("s3api", "list-object-versions", *target, "--max-keys", "1", "--no-paginate")
    if any(versions.get(key) for key in ("Versions", "DeleteMarkers")):
        raise RuntimeError("O bucket precisa estar vazio e sem versões ou marcadores.")

    ownership = aws("s3api", "get-bucket-ownership-controls", *target)["OwnershipControls"]
    if not any(rule["ObjectOwnership"] == "BucketOwnerEnforced" for rule in ownership["Rules"]):
        raise RuntimeError("O bucket precisa estar com BucketOwnerEnforced.")

    if aws("s3api", "get-bucket-policy-status", *target)["PolicyStatus"]["IsPublic"] is not False:
        raise RuntimeError("A política do bucket precisa ser privada.")

    if read_flags(aws, target) != BASELINE:
        raise RuntimeError("O bucket precisa começar com as quatro opções de bloqueio ativas.")
    return target


def read_flags(aws, target):
    return aws("s3api", "get-public-access-block", *target)["PublicAccessBlockConfiguration"]


def write_flags(aws, target, flags):
    aws(
        "s3api",
        "put-public-access-block",
        *target,
        "--public-access-block-configuration",
        json.dumps(flags),
    )


def completed_incident(aws, table, since, bucket):
    response = aws(
        "dynamodb",
        "scan",
        "--table-name",
        table,
        "--consistent-read",
        "--filter-expression",
        "#phase = :done AND created_at >= :since",
        "--expression-attribute-names",
        '{"#phase":"phase"}',
        "--expression-attribute-values",
        json.dumps({":done": {"S": "done"}, ":since": {"N": str(since)}}),
    )
    for item in response.get("Items", []):
        evidence = item["evidence"]["M"]
        signal = item["signal"]["M"]
        outcome = evidence["outcome"]["S"]
        if (
            outcome in ("remediated", "baseline_verified")
            and evidence["before"].get("M", {}).get("BlockPublicPolicy") == {"BOOL": False}
            and all(evidence["after"]["M"].get(flag) == {"BOOL": True} for flag in BASELINE)
            and {"S": bucket} in signal["buckets"]["L"]
        ):
            return {
                "incident_id": item["incident_id"]["S"],
                "source": signal["source"]["S"],
                "outcome": outcome,
                "BlockPublicPolicy": {"before": False, "after": True},
            }
    return None


def run(timeout):
    outputs = command_json(["terraform", "-chdir=infra", "output", "-json"])
    aws = aws_cli(outputs["region"]["value"])
    target = check_preconditions(aws, outputs)
    bucket = outputs["lab_bucket"]["value"]
    table = outputs["incident_table"]["value"]
    started = int(time.time())
    deadline = time.monotonic() + timeout
    verified = False

    try:
        write_flags(aws, target, DRIFT)
        print(
            "Desvio controlado aplicado. Aguardando evidência e releitura do S3.", file=sys.stderr
        )
        while time.monotonic() < deadline:
            if read_flags(aws, target) == BASELINE:
                incident = completed_incident(aws, table, started, bucket)
                if incident:
                    verified = True
                    print(json.dumps(incident, indent=2))
                    return
            time.sleep(8)
        raise RuntimeError("O prazo terminou sem evidência de conclusão no DynamoDB.")
    finally:
        if not verified:
            # Even an ambiguous or interrupted CLI response may have changed the bucket.
            write_flags(aws, target, BASELINE)
            if read_flags(aws, target) != BASELINE:
                raise RuntimeError("Restauração de segurança inconclusiva. Consulte o runbook.")
            print("O script restaurou e verificou o bloqueio do bucket.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-sandbox",
        action="store_true",
        help="Confirma a execução contra a conta sandbox usada pelo Terraform.",
    )
    parser.add_argument("--timeout", type=int, default=420, metavar="SEGUNDOS")
    args = parser.parse_args()
    if not args.confirm_sandbox or not 30 <= args.timeout <= 900:
        parser.error("Use --confirm-sandbox e um timeout de 30 a 900 segundos.")
    try:
        run(args.timeout)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        parser.exit(1, f"Exercício incompleto. {exc}\n")


if __name__ == "__main__":
    main()
