# Models

`random_forest_model_v2.joblib` is the deployed Random Forest (primary detector).

* Bundle keys: `model` (scikit-learn `RandomForestClassifier`, 300 trees,
  `class_weight="balanced"`) and `feature_columns` (the 18 features in
  `src/features.py:FEATURE_COLUMNS`, same order).
* Classes `[0, 1]`; `1` = anomalous window. The code looks the anomaly class up
  by label (`ANOMALY_LABEL`), never by position.
* Trained with scikit-learn 1.7.2; `requirements.txt` pins that version because
  pickled forests are not guaranteed to load across versions.
* Version shown in the dashboard/database: `random_forest_model_v2@<sha256[:12]>`.

This file (2.8 MB) is **versioned in Git** so every deployment uses exactly the
model that CI validated. `random_forest_model.joblib` (v1) is kept locally for
reference only and is git-ignored. Validate any bundle with
`python manage.py check-model`.

The training scripts (`generate_logs.py`, `supervised_detector.py`, ...) are not
part of this repository; retraining must keep `FEATURE_COLUMNS` unchanged or
update `src/features.py` and the tests together.
