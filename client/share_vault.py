"""
Gestor simplificado de distribución de shares.

En un despliegue real cada share debería viajar por un canal seguro hacia
un custodio distinto (otro servicio, HSM, bóveda, etc.). Aquí modelamos
ese comportamiento persistiendo cada share en un contenedor separado dentro
de ``secure_storage_dir``. El servidor nunca recibe suficientes shares para
reconstruir la clave; la recuperación exige contactar manualmente con los
custodios.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Iterable, List, Tuple


class SecureShareVault:
    """Almacena cada share en un contenedor lógico distinto."""

    def __init__(self, storage_dir: str, custodians: Iterable[str]) -> None:
        self.base_path = Path(storage_dir).expanduser().resolve()
        self.custodians: List[str] = list(custodians)
        if not self.custodians:
            raise ValueError("Debe definirse al menos un custodio para almacenar shares.")
        self.base_path.mkdir(parents=True, exist_ok=True)

    def distribute(self, shares: List[Tuple[int, int]]) -> List[dict]:
        """
        Guarda cada share bajo un custodio distinto y devuelve referencias
        opacas que pueden registrarse junto al mensaje cifrado.
        """
        if len(shares) < len(self.custodians):
            raise ValueError("Número de shares insuficiente para los custodios configurados.")

        references: List[dict] = []
        timestamp = int(time.time())

        for index, custodian in enumerate(self.custodians):
            custodian_dir = self.base_path / custodian
            custodian_dir.mkdir(parents=True, exist_ok=True)

            share = shares[index]
            share_id = f"{timestamp}_{uuid.uuid4().hex}"
            payload = {
                "x": share[0],
                "y": share[1],
                "generated_at": timestamp,
            }

            share_file = custodian_dir / f"{share_id}.json"
            with share_file.open("w", encoding="utf-8") as handler:
                json.dump(payload, handler, separators=(",", ":"))

            references.append(
                {
                    "custodian": custodian,
                    "share_id": share_id,
                    "location": str(share_file),
                }
            )

        return references
