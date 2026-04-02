from app.config import settings

def get_ai_summary(url: str, categories: list, score: int, grade: str) -> str | None:
    if not settings.anthropic_api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        failures = []
        for cat in categories:
            for f in cat.get("findings", []):
                if f.get("status") == "fail" and f.get("severity") in ("critical", "high"):
                    failures.append(f"[{f['severity'].upper()}] {f['title']}")
        top = "\n".join(failures[:5]) if failures else "None"
        prompt = (
            f"Security scan of {url}: score {score}/100 (Grade {grade}).\n"
            f"Top issues:\n{top}\n\n"
            f"Write 2 plain-English sentences: biggest risk and the single most important fix. No markdown."
        )
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text
    except Exception:
        return None
