"""
ML Service — Classification automatique de la famille CWE d'une
vulnérabilité à partir du texte de sa description.

CONTEXTE :
  Certains findings Nuclei (notamment les templates custom ou peu
  documentés) ne renseignent pas toujours un CWE clair. Ce service
  fournit une estimation automatique basée sur un modèle TF-IDF +
  LinearSVC entraîné sur ~140k CVE historiques (dataset NVD/CWE
  1999-2025), restreint aux 15 familles de vulnérabilités les plus
  fréquentes.

  Ce n'est PAS un remplacement de l'enrichissement NVD officiel
  (nvd_service.py) -- c'est un filet de sécurité pour les cas où
  aucun CWE fiable n'est disponible immédiatement après le scan.

CHARGEMENT :
  Le modèle est chargé une seule fois au niveau module (pas à
  chaque appel), les fichiers .pkl doivent être présents dans
  app/ml_models/. Si les fichiers sont absents (ex: pas encore
  déployés), le service se dégrade proprement : predict_cwe()
  retourne None plutôt que de lever une exception, pour ne jamais
  bloquer la création d'une vulnérabilité faute de modèle ML.
"""

import os
import joblib
import logging

logger = logging.getLogger("bug_bounty")

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "ml_models")
_MODEL_PATH = os.path.join(_MODEL_DIR, "cwe_text_model.pkl")
_VECTORIZER_PATH = os.path.join(_MODEL_DIR, "cwe_tfidf_vectorizer.pkl")

# Confiance minimale (marge de décision LinearSVC) en dessous de
# laquelle on préfère ne rien retourner plutôt que d'afficher une
# estimation peu fiable.
_MIN_CONFIDENCE = 0.15

_model = None
_vectorizer = None
_load_error = None

try:
    _model = joblib.load(_MODEL_PATH)
    _vectorizer = joblib.load(_VECTORIZER_PATH)
    logger.info("ML service : modèle CWE chargé avec succès (%d classes)",
                len(_model.classes_))
except Exception as e:
    _load_error = str(e)
    logger.warning(
        "ML service : modèle CWE indisponible (%s). "
        "predict_cwe() retournera toujours None.", e
    )


def is_available() -> bool:
    """True si le modèle a été chargé avec succès."""
    return _model is not None and _vectorizer is not None


def predict_cwe(description: str) -> dict | None:
    """
    Prédit la famille CWE la plus probable à partir d'un texte de
    description de vulnérabilité.

    Args:
        description: texte libre décrivant la vulnérabilité
                      (ex: le champ `info.description` d'un template
                      Nuclei, ou une description saisie manuellement).

    Returns:
        dict {"cwe_id": str, "confidence": float, "source": "ml_estimate"}
        ou None si le modèle est indisponible, la description vide,
        ou la confiance trop faible pour être affichée.

    Usage:
        result = ml_service.predict_cwe(vuln.description)
        if result:
            vuln.cwe_id = result["cwe_id"]
            vuln.cwe_source = "ml_estimate"  # distingue d'un CWE officiel NVD
    """
    if not is_available():
        return None

    if not description or not description.strip():
        return None

    X = _vectorizer.transform([description])
    prediction = _model.predict(X)[0]

    # decision_function retourne la marge de séparation par classe
    # (LinearSVC n'a pas de predict_proba natif) -- on l'utilise comme
    # proxy de confiance.
    decision_scores = _model.decision_function(X)[0]
    confidence = float(max(decision_scores) - sorted(decision_scores)[-2])
    # écart entre la meilleure et la deuxième meilleure classe :
    # un écart faible = le modèle hésite entre deux catégories proches

    if confidence < _MIN_CONFIDENCE:
        logger.debug("ML service : confiance trop faible (%.3f) pour '%s...'",
                     confidence, description[:50])
        return None

    return {
        "cwe_id": prediction,
        "confidence": round(confidence, 3),
        "source": "ml_estimate",
    }