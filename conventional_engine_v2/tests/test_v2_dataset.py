import json
from pathlib import Path
import pytest
from conventional_engine import process

DATA = json.loads((Path(__file__).parents[1] / "test_data" / "v2_scenarios.json").read_text(encoding="utf-8"))

@pytest.mark.parametrize("case", DATA, ids=lambda c: c["id"] + "-" + c["name"].replace(" ", "_"))
def test_v2_scenario(case):
    result = process(case["input_format"], case["payload"], case["context"])
    assert result["status"] == case["expected_status"], (case["id"], case["name"], result)
    if case["expected_issue_code"]:
        actual = [issue["code"] for issue in result["issues"]]
        assert case["expected_issue_code"] in actual, (case["id"], actual, result)

def test_all_five_categories_are_represented():
    assert {c["category"] for c in DATA} == {"api_backend", "etl", "sre_devops", "data_platform", "enterprise"}

def test_dataset_has_at_least_60_cases():
    assert len(DATA) >= 60
