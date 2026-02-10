import importlib
import unittest
from unittest import mock


class FakeSnap:
    def __init__(self, data, exists):
        self._data = data
        self.exists = exists

    def to_dict(self):
        return self._data


class FakeDocRef:
    def __init__(self, data, error=None):
        self._data = data
        self._error = error

    def get(self):
        if self._error:
            raise self._error
        return FakeSnap(self._data, bool(self._data))


class FakeCollection:
    def __init__(self, docs=None, errors=None):
        self._docs = docs or {}
        self._errors = errors or {}

    def document(self, doc_id):
        return FakeDocRef(self._docs.get(doc_id), self._errors.get(doc_id))


class FakeDB:
    def __init__(self, collections=None, errors=None):
        self._collections = collections or {}
        self._errors = errors or {}

    def collection(self, name):
        return FakeCollection(self._collections.get(name), self._errors.get(name))


class ResolveNdcDisplayNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._patched = mock.patch("google.cloud.firestore.Client", return_value=FakeDB())
        cls._patched.start()
        cls.main = importlib.import_module("main")

    @classmethod
    def tearDownClass(cls):
        cls._patched.stop()

    def test_override_beats_cache(self):
        fake_db = FakeDB(
            collections={
                "ndc_alias_overrides": {"123": {"display_name": "Override Name"}},
                "ndc_name_cache_v1": {"123": {"name": "Cache Name"}},
            }
        )
        self.main.db = fake_db
        self.assertEqual(self.main.resolve_ndc_display_name("123"), "Override Name")

    def test_cache_beats_fallback(self):
        fake_db = FakeDB(
            collections={
                "ndc_name_cache_v1": {"456": {"name": "Cache Name"}},
            }
        )
        self.main.db = fake_db
        self.assertEqual(self.main.resolve_ndc_display_name("456"), "Cache Name")

    def test_errors_fall_back_cleanly(self):
        fake_db = FakeDB(
            errors={
                "ndc_alias_overrides": {"789": RuntimeError("boom")},
                "ndc_name_cache_v1": {"789": RuntimeError("boom")},
            }
        )
        self.main.db = fake_db
        self.assertEqual(self.main.resolve_ndc_display_name("789"), "789")


if __name__ == "__main__":
    unittest.main()
