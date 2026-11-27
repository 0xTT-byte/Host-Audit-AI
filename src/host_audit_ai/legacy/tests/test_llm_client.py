from unittest.mock import MagicMock, patch
from host_audit.llm_client import call_ollama, DEFAULT_MODEL
from host_audit.schema import TriageReport, AttackChain


def test_call_ollama_mocked():
    sample_response_data = {
        "executive_summary": "High risk due to critical postgres exposure and container breakout.",
        "attack_chains": [
            {
                "name": "DB Foothold to Root",
                "severity": "critical",
                "involved_rule_ids": ["EXP-002", "CNT-001"],
                "steps": ["Connect to exposed port 5432", "Break out via privileged mode"],
                "verify_cmds": ["nc -zv host 5432"],
                "fix_commands": ["ufw deny 5432"],
            }
        ],
        "false_positive_checks": ["Check if port 5432 is restricted at network boundary"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "content": TriageReport(**sample_response_data).model_dump_json()
        }
    }

    dummy_findings = {
        "host": "test-host",
        "findings": [
            {
                "rule_id": f"TEST-{i:03d}",
                "domain": "exposure",
                "severity": "high",
                "priority_score": 18,
                "title": f"Test finding {i}",
                "target": f"target:{i}",
                "evidence": f"evidence {i}",
                "verify_cmd": "echo test",
            }
            for i in range(30)  # More than 25 to verify truncation
        ]
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = call_ollama(
            model=DEFAULT_MODEL,
            findings_payload=dummy_findings,
            ollama_url="http://localhost:11434"
        )

        assert mock_post.called
        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "http://localhost:11434/api/chat"
        body = call_kwargs["json"]

        assert body["model"] == DEFAULT_MODEL
        assert body["options"]["temperature"] == 0.15
        assert body["options"]["num_ctx"] == 8192
        assert body["options"]["num_predict"] == 2048
        assert "format" in body
        assert "<FINDINGS_DATA>" in body["messages"][1]["content"]

        # Verify only top 25 findings sent
        content = body["messages"][1]["content"]
        assert "TEST-024" in content
        assert "TEST-025" not in content

        assert isinstance(result, TriageReport)
        assert len(result.attack_chains) == 1
        assert result.attack_chains[0].severity == "critical"
