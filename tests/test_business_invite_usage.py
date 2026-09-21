"""Removed invitation-limit controls stay absent from the standalone app."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_mother_pages_do_not_render_limit_or_usage_editors():
    sources = [text("frontend/src/pages/GptPlans.tsx")]
    for source in sources:
        assert "<BusinessInviteLimitSettings" not in source
        assert "<BusinessInviteUsageEditor" not in source


def test_invitation_summary_displays_daily_and_total_successes():
    component = text("frontend/src/components/BusinessInviteQuotaSummary.tsx")
    assert "今日成功" in component
    assert "累计成功" in component
    assert "data-business-invite-stats" in component


def test_old_mutation_endpoints_are_retired():
    source = text("api/gpt_plans.py")
    assert source.count("邀请已用次数不再支持人工调整") == 2
    assert source.count("本项目已取消 BUSINESS 邀请次数限制") == 2
