from pathlib import Path

def test_project_core_files_exist():
    assert Path("scripts/collect.py").exists()
    assert Path("scripts/normalize.py").exists()
    assert Path("scripts/score.py").exists()
    assert Path("scripts/build_report.py").exists()
    assert Path("docs/methodology.md").exists()
    assert Path("docs/finding_schema.md").exists()