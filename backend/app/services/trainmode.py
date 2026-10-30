"""
Classification NLP : prédire la catégorie CWE (type de vulnérabilité)
à partir du texte de DESCRIPTION uniquement -- sans CVSS, sans aucune
autre donnée structurée qui "trahirait" la réponse.

C'est un problème NLP multi-classe légitime : contrairement au score
CVSS -> SEVERITY (relation quasi-déterministe imposée par le NVD),
il n'existe pas de règle mécanique text -> CWE. Le modèle doit
réellement apprendre des motifs linguistiques (vocabulaire technique,
tournures de phrase) associés à chaque famille de vulnérabilité.

Pipeline :
  1. Filtrage : ne garder que le top N des CWE les plus fréquents
     (au-delà, trop peu d'exemples par classe pour apprendre quoi que
     ce soit -- et le nombre de classes total est énorme, ~300 CWE
     distincts avec des dizaines qui n'ont qu'un ou deux exemples)
  2. Vectorisation TF-IDF du texte (bag-of-words pondéré)
  3. Split train/test stratifié
  4. Validation croisée (5-fold stratifiée) sur le train set, avec
     TF-IDF recalculé à chaque fold via un Pipeline sklearn -- pour
     une estimation robuste et sans fuite de données
  5. Entraînement final LinearSVC sur tout le train set
  6. Évaluation sur le test set (F1 pondéré/macro, matrice de
     confusion, mots-clés les plus discriminants par classe)
"""

import pandas as pd
import numpy as np
import joblib
import json
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

RANDOM_STATE = 42
TOP_N_CWE = 15  # nombre de familles de vulnérabilités à distinguer
CV_FOLDS = 5

# ==============================================================================
# 1. CHARGEMENT + FILTRAGE
# ==============================================================================
print("Chargement du dataset...")
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "ml_models", "CVE_CWE_2025.csv")

df = pd.read_csv(DATASET_PATH, low_memory=False)

# On ne garde que les lignes avec un vrai CWE numéroté (on exclut les
# valeurs génériques type "NVD-CWE-Other" / "NVD-CWE-noinfo" qui ne
# décrivent aucune famille de vulnérabilité précise -- les inclure
# reviendrait à demander au modèle de deviner l'absence d'information)
df = df[df["CWE-ID"].str.startswith("CWE-", na=False)].copy()
df = df[df["DESCRIPTION"].notna()].copy()
print(f"  Après filtrage CWE valides : {len(df)} lignes")

# Top N des CWE les plus fréquents -- garantit assez d'exemples par
# classe pour un apprentissage significatif
top_cwe = df["CWE-ID"].value_counts().nlargest(TOP_N_CWE).index.tolist()
df = df[df["CWE-ID"].isin(top_cwe)].copy()
print(f"  Après filtrage top {TOP_N_CWE} CWE : {len(df)} lignes")
print(f"\nDistribution des classes conservées :")
print(df["CWE-ID"].value_counts())

# ==============================================================================
# 2. SPLIT TRAIN/TEST
# ==============================================================================
X_text = df["DESCRIPTION"]
y = df["CWE-ID"]

X_train_text, X_test_text, y_train, y_test = train_test_split(
    X_text, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)
print(f"\nTrain : {len(X_train_text)} | Test : {len(X_test_text)}")

# ==============================================================================
# 3. VALIDATION CROISÉE (sur le train set uniquement)
# ==============================================================================
# Le TF-IDF est recalculé à chaque fold via le Pipeline : le vocabulaire
# n'est jamais appris sur les données de validation du fold, donc pas
# de fuite d'information. C'est plus lent que vectoriser une seule fois,
# mais donne une estimation fiable de la performance réelle.
print(f"\nValidation croisée ({CV_FOLDS}-fold stratifiée) sur le train set...")

cv_pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=5000,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=5,
    )),
    ("svm", LinearSVC(class_weight="balanced", random_state=RANDOM_STATE, max_iter=5000)),
])

cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

cv_results = cross_validate(
    cv_pipeline, X_train_text, y_train,
    cv=cv,
    scoring=["accuracy", "f1_weighted", "f1_macro"],
    return_train_score=False,
    n_jobs=-1,
)

cv_acc_mean, cv_acc_std = cv_results["test_accuracy"].mean(), cv_results["test_accuracy"].std()
cv_f1w_mean, cv_f1w_std = cv_results["test_f1_weighted"].mean(), cv_results["test_f1_weighted"].std()
cv_f1m_mean, cv_f1m_std = cv_results["test_f1_macro"].mean(), cv_results["test_f1_macro"].std()

print(f"  Accuracy    : {cv_acc_mean:.4f} (+/- {cv_acc_std:.4f})")
print(f"  F1 pondéré  : {cv_f1w_mean:.4f} (+/- {cv_f1w_std:.4f})")
print(f"  F1 macro    : {cv_f1m_mean:.4f} (+/- {cv_f1m_std:.4f})")
print(f"  Scores F1 pondéré par fold : {np.round(cv_results['test_f1_weighted'], 4).tolist()}")

# ==============================================================================
# 4. VECTORISATION FINALE + ENTRAÎNEMENT SUR TOUT LE TRAIN SET
# ==============================================================================
print("\nVectorisation TF-IDF (fit final sur tout le train set)...")
vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english",
    ngram_range=(1, 2),   # unigrammes + bigrammes (ex: "buffer overflow")
    min_df=5,
)
X_train = vectorizer.fit_transform(X_train_text)
X_test = vectorizer.transform(X_test_text)
print(f"  Vocabulaire retenu : {len(vectorizer.vocabulary_)} termes")

print("\nEntraînement du LinearSVC final...")
model = LinearSVC(class_weight="balanced", random_state=RANDOM_STATE, max_iter=5000)
model.fit(X_train, y_train)

# ==============================================================================
# 5. ÉVALUATION SUR LE TEST SET (mise de côté, jamais vue avant)
# ==============================================================================
print("\nÉvaluation sur le test set...")
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
f1_weighted = f1_score(y_test, y_pred, average="weighted")
f1_macro = f1_score(y_test, y_pred, average="macro")

print(f"\nAccuracy globale             : {acc:.4f}")
print(f"F1-score pondéré             : {f1_weighted:.4f}")
print(f"F1-score macro (non pondéré) : {f1_macro:.4f}")

report = classification_report(y_test, y_pred, output_dict=True)
print("\nRapport détaillé par classe :")
print(classification_report(y_test, y_pred))

# Comparaison CV vs test set -- utile pour repérer un split test qui
# serait anormalement facile/difficile par rapport à la moyenne CV
print("\nComparaison validation croisée (train) vs test set final :")
print(f"  F1 pondéré CV   : {cv_f1w_mean:.4f} (+/- {cv_f1w_std:.4f})")
print(f"  F1 pondéré test : {f1_weighted:.4f}")

# Matrice de confusion
labels_order = sorted(y.unique())
cm = confusion_matrix(y_test, y_pred, labels=labels_order)

plt.figure(figsize=(11, 9))
sns.heatmap(
    cm, annot=True, fmt="d", cmap="Blues",
    xticklabels=labels_order, yticklabels=labels_order
)
plt.xlabel("Prédiction")
plt.ylabel("Vraie valeur")
plt.title("Matrice de confusion — Classification CWE depuis le texte")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig("confusion_matrix_cwe.png", dpi=150)
print("\nMatrice de confusion sauvegardée : confusion_matrix_cwe.png")

# Mots les plus discriminants par classe (interprétabilité du modèle
# linéaire -- équivalent du feature_importance pour du texte)
print("\nTermes les plus discriminants par CWE (top 8) :")
feature_names = np.array(vectorizer.get_feature_names_out())
top_terms_per_class = {}
for i, cwe in enumerate(model.classes_):
    coefs = model.coef_[i]
    top_idx = np.argsort(coefs)[-8:][::-1]
    top_terms = feature_names[top_idx].tolist()
    top_terms_per_class[cwe] = top_terms
    print(f"  {cwe:20s} : {', '.join(top_terms)}")

# ==============================================================================
# 6. SAUVEGARDE
# ==============================================================================
joblib.dump(model, "cwe_text_model.pkl")
joblib.dump(vectorizer, "cwe_tfidf_vectorizer.pkl")

metrics_summary = {
    "accuracy": acc,
    "f1_weighted": f1_weighted,
    "f1_macro": f1_macro,
    "cross_validation": {
        "folds": CV_FOLDS,
        "accuracy_mean": cv_acc_mean,
        "accuracy_std": cv_acc_std,
        "f1_weighted_mean": cv_f1w_mean,
        "f1_weighted_std": cv_f1w_std,
        "f1_macro_mean": cv_f1m_mean,
        "f1_macro_std": cv_f1m_std,
        "f1_weighted_per_fold": cv_results["test_f1_weighted"].tolist(),
    },
    "n_train": len(X_train_text),
    "n_test": len(X_test_text),
    "n_classes": TOP_N_CWE,
    "classification_report": report,
    "top_terms_per_class": top_terms_per_class,
}
with open("metrics_summary_cwe.json", "w") as f:
    json.dump(metrics_summary, f, indent=2)

print("\nModèle et artefacts sauvegardés :")
print("  - cwe_text_model.pkl")
print("  - cwe_tfidf_vectorizer.pkl")
print("  - metrics_summary_cwe.json")
print("\nTerminé.")