"""Isolation Forest with bounded, non-executable, reproducible JSON artifacts.

The artifact contains normal training observations, settings, a SHA-256 integrity
fingerprint and provenance. Loading validates the artifact before rebuilding the
forest with its original seed and scikit-learn version. It never deserializes
Python objects. A fingerprint detects damage; it is not a digital signature.

The contamination parameter selects a score threshold, not an attack likelihood.
Scores are -score_samples so a higher score means more anomalous. A score above
the threshold is a model finding, not proof of an intrusion.
"""

import copy
import hashlib
import json
import math
import numbers
import os
import tempfile
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES

if TYPE_CHECKING:
    from .config import MLConfig

MAX_TRAINING_ROWS = 10_000
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
FORMAT_VERSION = 1
ALGORITHM = "sklearn.ensemble.IsolationForest"
SETTING_KEYS = {"window_seconds", "min_samples", "contamination", "n_estimators", "random_state"}
ARTIFACT_KEYS = {
    "format_version",
    "algorithm",
    "feature_names",
    "sklearn_version",
    "settings",
    "provenance",
    "trained_at",
    "training_rows",
    "threshold",
    "fingerprint",
}


class ModelValidationError(ValueError):
    """The data/artifact cannot safely describe this model and feature schema."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _fingerprint(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical({key: value for key, value in payload.items() if key != "fingerprint"})
    ).hexdigest()


def _validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, dict) or set(settings) != SETTING_KEYS:
        raise ModelValidationError("Modelindstillingerne har en ukendt struktur.")
    integer_bounds = {
        "window_seconds": (1, 86400),
        "min_samples": (20, MAX_TRAINING_ROWS),
        "n_estimators": (16, 512),
        "random_state": (0, 2**32 - 1),
    }
    for key, (minimum, maximum) in integer_bounds.items():
        if type(settings[key]) is not int or not minimum <= settings[key] <= maximum:
            raise ModelValidationError(f"Ugyldig modelindstilling: {key}.")
    contamination = settings["contamination"]
    if isinstance(contamination, bool) or not isinstance(contamination, numbers.Real):
        raise ModelValidationError("contamination skal være et tal mellem 0 og 0.5.")
    if not math.isfinite(contamination) or not 0 < contamination <= 0.5:
        raise ModelValidationError("contamination skal være større end 0 og højst 0.5.")
    return {**settings, "contamination": float(contamination)}


def _validate_rows(rows: Sequence[Sequence[float]], minimum: int = 1) -> np.ndarray:
    if isinstance(rows, (str, bytes, dict)):
        raise ModelValidationError("Modelinput skal være en tabel med numeriske features.")
    try:
        row_count = len(rows)
    except TypeError as exc:
        raise ModelValidationError("Modelinput skal have et afgrænset antal rækker.") from exc
    if not minimum <= row_count <= MAX_TRAINING_ROWS:
        raise ModelValidationError(
            f"Der kræves {minimum} til {MAX_TRAINING_ROWS} observationsrækker."
        )
    clean: list[list[float]] = []
    for row in rows:
        if isinstance(row, (str, bytes, dict)):
            raise ModelValidationError("En observation skal være en liste med features.")
        try:
            if len(row) != len(FEATURE_NAMES):
                raise ModelValidationError(
                    f"Der kræves præcis {len(FEATURE_NAMES)} features pr. observation."
                )
        except TypeError as exc:
            raise ModelValidationError(
                "En observation skal have den faste featurestruktur."
            ) from exc
        if any(
            isinstance(value, (bool, np.bool_)) or not isinstance(value, numbers.Real)
            for value in row
        ):
            raise ModelValidationError("Features må kun indeholde reelle tal.")
        numeric = [float(value) for value in row]
        if not all(math.isfinite(value) for value in numeric):
            raise ModelValidationError("Features indeholder NaN eller uendelige værdier.")
        failed, success, users, ratio, sine, cosine = numeric
        if any(value < 0 or value > 1_000_000 or not value.is_integer() for value in numeric[:3]):
            raise ModelValidationError(
                "Hændelsesantal skal være ikke-negative heltal inden for grænsen."
            )
        total = failed + success
        if total < 1 or not 1 <= users <= total:
            raise ModelValidationError(
                "Aktive observationsvinduer skal have hændelser og gyldige brugertællinger."
            )
        if not 0 <= ratio <= 1 or not math.isclose(
            ratio, failed / total, rel_tol=1e-6, abs_tol=1e-6
        ):
            raise ModelValidationError("Andelen af fejlede forsøg stemmer ikke med tællingerne.")
        if not (-1 <= sine <= 1 and -1 <= cosine <= 1) or not math.isclose(
            sine * sine + cosine * cosine, 1.0, abs_tol=1e-5
        ):
            raise ModelValidationError("Tidsfeatures skal være sinus og cosinus for samme UTC-tid.")
        clean.append(numeric)
    return np.asarray(clean, dtype=np.float64)


def _validate_provenance(provenance: Any) -> str:
    if not isinstance(provenance, str) or not 1 <= len(provenance.strip()) <= 2000:
        raise ModelValidationError("Beskriv datagrundlaget med 1 til 2000 tegn.")
    return provenance.strip()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelValidationError("Modelfilen indeholder gentagne JSON-felter.")
        result[key] = value
    return result


class IsolationForestDetector:
    """One immutable fitted model for one explicitly identified feature schema."""

    def __init__(
        self, rows: np.ndarray, settings: dict[str, Any], provenance: str, trained_at: str
    ) -> None:
        self._rows = rows.copy()
        self._settings = dict(settings)
        self._model = IsolationForest(
            n_estimators=settings["n_estimators"],
            max_samples=min(256, len(rows)),
            contamination=settings["contamination"],
            random_state=settings["random_state"],
            n_jobs=1,
        )
        self._model.fit(self._rows)
        self._threshold = float(-self._model.offset_)
        self._payload = {
            "format_version": FORMAT_VERSION,
            "algorithm": ALGORITHM,
            "feature_names": list(FEATURE_NAMES),
            "sklearn_version": sklearn.__version__,
            "settings": dict(settings),
            "provenance": provenance,
            "trained_at": trained_at,
            "training_rows": self._rows.tolist(),
            "threshold": self._threshold,
        }
        self._payload["fingerprint"] = _fingerprint(self._payload)
        self._metadata = {
            "version": "ssh-if-" + self._payload["fingerprint"][:16],
            "provenance": provenance,
            "trained_at": trained_at,
            "sample_count": len(rows),
            "feature_names": list(FEATURE_NAMES),
            "threshold": self._threshold,
            "sklearn_version": sklearn.__version__,
            "window_seconds": settings["window_seconds"],
            "contamination": settings["contamination"],
            "settings": dict(settings),
            "fingerprint": self._payload["fingerprint"],
            "score_direction": "higher_is_more_anomalous",
            "observations": "event_driven_per_source_rolling_window",
        }

    @property
    def metadata(self) -> dict[str, Any]:
        return copy.deepcopy(self._metadata)

    @classmethod
    def train(
        cls, rows: Sequence[Sequence[float]], config: "MLConfig", provenance: str
    ) -> "IsolationForestDetector":
        try:
            settings = _validate_settings({key: getattr(config, key) for key in SETTING_KEYS})
        except AttributeError as exc:
            raise ModelValidationError("Modelkonfigurationen mangler et påkrævet felt.") from exc
        matrix = _validate_rows(rows, settings["min_samples"])
        cls._check_variation(matrix)
        label = _validate_provenance(provenance)
        trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return cls(matrix, settings, label, trained_at)

    @staticmethod
    def _check_variation(matrix: np.ndarray) -> None:
        if len(np.unique(matrix, axis=0)) < 4 or not np.any(np.ptp(matrix[:, :3], axis=0) > 0):
            raise ModelValidationError(
                "Træningsdata mangler variation i normalaktiviteten; gentagne ens rækker er utilstrækkelige."
            )

    def score(self, values: Sequence[float]) -> dict[str, Any]:
        matrix = _validate_rows([values])
        score = float(-self._model.score_samples(matrix)[0])
        return {
            "score": score,
            "threshold": self._threshold,
            "is_anomaly": bool(score > self._threshold),
            "model_version": self._metadata["version"],
            "features": dict(zip(FEATURE_NAMES, matrix[0].tolist(), strict=True)),
        }

    def save(self, path: Path | str) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        encoded = _canonical(self._payload)
        if len(encoded) > MAX_ARTIFACT_BYTES:
            raise ModelValidationError("Modelfilen overskrider størrelsesgrænsen.")
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=".model-", suffix=".tmp", delete=False
            ) as handle:
                temporary = handle.name
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o640)
            os.replace(temporary, target)
            temporary = None
            # Directory fsync is available on the intended Linux/WSL deployment.
            if hasattr(os, "O_DIRECTORY"):
                descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    @classmethod
    def load(cls, path: Path | str) -> "IsolationForestDetector":
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ModelValidationError("Modelfilen overskrider størrelsesgrænsen.")
        try:
            payload = json.loads(raw, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ModelValidationError("Modelfilen er ikke gyldig JSON.") from exc
        if not isinstance(payload, dict) or set(payload) != ARTIFACT_KEYS:
            raise ModelValidationError("Modelfilen har en ukendt struktur.")
        if (
            type(payload["format_version"]) is not int
            or payload["format_version"] != FORMAT_VERSION
        ):
            raise ModelValidationError("Modelfilens formatversion understøttes ikke.")
        if payload["algorithm"] != ALGORITHM or payload["feature_names"] != list(FEATURE_NAMES):
            raise ModelValidationError("Modellen har en anden algoritme eller featuredefinition.")
        if payload["sklearn_version"] != sklearn.__version__:
            raise ModelValidationError(
                "Modellen kræver samme scikit-learn-version som ved træning; genoptræn i dette miljø."
            )
        settings = _validate_settings(payload["settings"])
        provenance = _validate_provenance(payload["provenance"])
        try:
            trained_at = datetime.fromisoformat(payload["trained_at"])
            if trained_at.utcoffset() is None or trained_at.utcoffset().total_seconds() != 0:
                raise ValueError("not UTC")
        except (ValueError, TypeError, OverflowError) as exc:
            raise ModelValidationError(
                "Modellen mangler et gyldigt UTC-træningstidspunkt."
            ) from exc
        threshold = payload["threshold"]
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold)
            or not 0 <= threshold <= 1
        ):
            raise ModelValidationError("Modellen har en ugyldig alarmgrænse.")
        try:
            checksum = _fingerprint(payload)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ModelValidationError("Modellen indeholder ugyldige JSON-værdier.") from exc
        if not isinstance(payload["fingerprint"], str) or payload["fingerprint"] != checksum:
            raise ModelValidationError(
                "Modelfilens fingeraftryk stemmer ikke; filen kan være beskadiget."
            )
        matrix = _validate_rows(payload["training_rows"], settings["min_samples"])
        cls._check_variation(matrix)
        result = cls(matrix, settings, provenance, payload["trained_at"])
        if not math.isclose(result._threshold, threshold, rel_tol=1e-12, abs_tol=1e-12):
            raise ModelValidationError("Modellen kunne ikke genopbygges med samme alarmgrænse.")
        if result._payload["fingerprint"] != checksum:
            raise ModelValidationError("Modellens indhold kunne ikke genskabes identisk.")
        return result
