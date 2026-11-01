#!/usr/bin/env bash
# DetectIQ Test Runner & Report Generator (Bash / Git Bash)
# Usage: ./run_tests.sh [unit|system|all]

TYPE=${1:-all}
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_EXE="$ROOT_DIR/backend/venv/Scripts/python.exe"
REPORTS_DIR="$ROOT_DIR/tests/reports"

mkdir -p "$REPORTS_DIR"

echo -e "\n========================================================"
echo -e "       DetectIQ Test Suite & Report Generator           "
echo -e "========================================================\n"

HTML_PLUGIN=$("$PYTHON_EXE" -m pip list | grep "pytest-html" || true)

if [ "$TYPE" = "unit" ] || [ "$TYPE" = "all" ]; then
    echo -e "[*] Running Unit Tests (Mocked / Logic Scope)..."
    UNIT_REPORT="$REPORTS_DIR/unit_test_report.html"
    if [ -n "$HTML_PLUGIN" ]; then
        "$PYTHON_EXE" -m pytest "$ROOT_DIR/tests/unit" -v --html="$UNIT_REPORT" --self-contained-html
        echo -e "[+] Unit test report generated: $UNIT_REPORT"
    else
        "$PYTHON_EXE" -m pytest "$ROOT_DIR/tests/unit" -v
    fi
fi

if [ "$TYPE" = "system" ] || [ "$TYPE" = "all" ]; then
    echo -e "\n[*] Running System Tests (Live Pipeline Scope)..."
    echo -e "    Note: Requires backend server running on http://127.0.0.1:8000"
    SYSTEM_REPORT="$REPORTS_DIR/system_test_report.html"
    if [ -n "$HTML_PLUGIN" ]; then
        "$PYTHON_EXE" -m pytest "$ROOT_DIR/tests/system" -v --html="$SYSTEM_REPORT" --self-contained-html
        echo -e "[+] System test report generated: $SYSTEM_REPORT"
    else
        "$PYTHON_EXE" -m pytest "$ROOT_DIR/tests/system" -v
    fi
fi

echo -e "\n[✓] Testing complete!\n"

