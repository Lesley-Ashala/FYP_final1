import math

import pandas as pd
from django.test import SimpleTestCase

from monitoring.services import extract_features


class FeatureExtractionTests(SimpleTestCase):
    def test_extract_features_computes_expected_values_and_role_zscore(self):
        frame = pd.DataFrame(
            [
                {
                    "id": 1,
                    "user_id": 101,
                    "role_snapshot": "doctor",
                    "patient_record_id": 501,
                    "accessed_at": "2026-03-01T10:00:00Z",
                },
                {
                    "id": 2,
                    "user_id": 101,
                    "role_snapshot": "doctor",
                    "patient_record_id": 502,
                    "accessed_at": "2026-03-01T12:00:00Z",
                },
                {
                    "id": 3,
                    "user_id": 101,
                    "role_snapshot": "doctor",
                    "patient_record_id": 502,
                    "accessed_at": "2026-03-01T14:00:00Z",
                },
                {
                    "id": 4,
                    "user_id": 102,
                    "role_snapshot": "doctor",
                    "patient_record_id": 503,
                    "accessed_at": "2026-03-01T10:00:00Z",
                },
            ]
        )

        features = extract_features(frame)

        user_101 = features.loc[features["user_id"] == 101].iloc[0]
        user_102 = features.loc[features["user_id"] == 102].iloc[0]

        self.assertEqual(int(user_101["access_frequency_per_user"]), 3)
        self.assertEqual(int(user_101["unique_patients_accessed"]), 2)
        self.assertAlmostEqual(float(user_101["time_of_day_access_deviation"]), 2.0, places=4)
        self.assertAlmostEqual(
            float(user_101["role_based_access_deviation"]),
            1.0 / math.sqrt(2.0),
            places=4,
        )

        self.assertEqual(int(user_102["access_frequency_per_user"]), 1)
        self.assertEqual(int(user_102["unique_patients_accessed"]), 1)
        self.assertAlmostEqual(float(user_102["time_of_day_access_deviation"]), 0.0, places=4)
        self.assertAlmostEqual(
            float(user_102["role_based_access_deviation"]),
            -1.0 / math.sqrt(2.0),
            places=4,
        )

    def test_extract_features_returns_empty_dataframe_for_empty_input(self):
        frame = pd.DataFrame(
            columns=["id", "user_id", "role_snapshot", "patient_record_id", "accessed_at"]
        )
        features = extract_features(frame)
        self.assertTrue(features.empty)
        self.assertIn("access_frequency_per_user", features.columns)
        self.assertIn("time_of_day_access_deviation", features.columns)
        self.assertIn("unique_patients_accessed", features.columns)
        self.assertIn("role_based_access_deviation", features.columns)

