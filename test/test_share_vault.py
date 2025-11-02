import json
from pathlib import Path

from client.share_vault import SecureShareVault


def test_secure_share_vault_creates_individual_files(tmp_path):
    custodians = ["c1", "c2", "c3"]
    vault = SecureShareVault(str(tmp_path), custodians)

    shares = [(idx + 1, (idx + 1) * 111) for idx in range(len(custodians))]
    references = vault.distribute(shares)

    assert len(references) == len(custodians)

    for ref, expected_share in zip(references, shares):
        file_path = Path(ref["location"])
        assert file_path.exists()

        payload = json.loads(file_path.read_text(encoding="utf-8"))
        assert payload["x"] == expected_share[0]
        assert payload["y"] == expected_share[1]
        assert payload["generated_at"] > 0
