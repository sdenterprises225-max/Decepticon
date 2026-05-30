from __future__ import annotations

from decepticon.tools.cloud.aws import analyze_iam_policy


class TestNotActionSemantics:
    def test_notaction_star_resource_is_critical(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert "NotAction" in f.title
        assert "s3:getobject" in f.detail

    def test_notaction_scoped_resource_is_high(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:CreateAccessKey",
                    "Resource": "arn:aws:iam::123456789012:user/bob",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert "NotAction" in f.title
        assert "iam:createaccesskey" in f.detail

    def test_notaction_does_not_match_primitives_as_if_action(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert not any("CreateAccessKey privilege escalation" in f.title for f in findings)

    def test_notaction_list_star_resource_is_critical(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert any(f.severity == "critical" for f in findings)
        assert any("NotAction" in f.title for f in findings)

    def test_action_path_still_works_after_fix(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert any("CreateAccessKey" in f.title for f in findings)

    def test_deny_notaction_is_ignored(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "NotAction": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
        findings = analyze_iam_policy(policy)
        assert len(findings) == 0
