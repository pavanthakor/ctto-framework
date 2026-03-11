"""Test if calculate_threat_score can be imported and works correctly."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from modules.analysis.threat_score import calculate_threat_score
    score = calculate_threat_score("admin", "curl/8.5.0", "")
    print(f"Import OK, score for admin+curl = {score}")
except Exception as e:
    print(f"Import FAILED: {e}")
