"""osint module — open-source intelligence & social engineering recon.

Provides:
  - Email intelligence (validation / EmailRep.io / HIBP / Hunter.io / SMTP / pattern guessing)
  - Username cross-platform search (30+ platforms: GitHub, Twitter, Reddit ...)
  - Domain intelligence (WHOIS / DNS / certificate transparency / Wayback Machine)
  - Social media intelligence (GitHub user / email-commit cross-reference)
  - Breach check (HaveIBeenPwned)
  - Report generation
  - Identity profile (network / geo / domain)

All submodules are lazy-loaded via __getattr__ to save ~100ms at import time.

Usage:
    from osint import email_lookup, username_search, domain_intel
    result = email_lookup("user@example.com")
"""

import importlib

_SYMBOL_MAP = {
    # -- email_lookup --
    "email_lookup": ("osint.email_lookup", "email_lookup"),
    "EmailIntelResult": ("osint.email_lookup", "EmailIntelResult"),
    "EmailFormat": ("osint.email_lookup", "EmailFormat"),
    # -- username_search --
    "username_search": ("osint.username_search", "username_search"),
    "UsernameSearchResult": ("osint.username_search", "UsernameSearchResult"),
    "PlatformResult": ("osint.username_search", "PlatformResult"),
    # -- domain_intel --
    "domain_intel": ("osint.domain_intel", "domain_intel"),
    "DomainIntelResult": ("osint.domain_intel", "DomainIntelResult"),
    "WhoisInfo": ("osint.domain_intel", "WhoisInfo"),
    # -- social_lookup --
    "social_lookup": ("osint.social_lookup", "social_lookup"),
    "SocialIntelResult": ("osint.social_lookup", "SocialIntelResult"),
    "GitHubUser": ("osint.social_lookup", "GitHubUser"),
    # -- breach_check --
    "breach_check": ("osint.breach_check", "breach_check"),
    "BreachCheckResult": ("osint.breach_check", "BreachCheckResult"),
    "BreachInfo": ("osint.breach_check", "BreachInfo"),
    # -- runner --
    "run_osint": ("osint.runner", "run_osint"),
    "OsintResult": ("osint.runner", "OsintResult"),
    # -- report --
    "generate_report": ("osint.report", "generate_report"),
    # -- artifacts --
    "OsintArtifact": ("osint.artifacts", "OsintArtifact"),
    "OsintGraph": ("osint.artifacts", "OsintGraph"),
    "normalize": ("osint.artifacts", "normalize"),
    "synonym_key": ("osint.artifacts", "synonym_key"),
    # -- sources --
    "collect": ("osint.sources", "collect"),
    "list_sources": ("osint.sources", "list_sources"),
    # -- graph --
    "expand_graph": ("osint.graph_engine", "expand"),
    "render_graph": ("osint.graph_viz", "render"),
    # -- agent --
    "run_agent": ("osint.osint_agent", "run_agent"),
    "OsintAgentResult": ("osint.osint_agent", "OsintAgentResult"),
    "verify_claims": ("osint.verify", "verify_claims"),
    # -- identity --
    "identity_profile": ("osint.identity", "identity_profile"),
    "IdentityProfile": ("osint.identity", "IdentityProfile"),
    # -- stealth (polite collection) --
    "StealthSession": ("osint.stealth_session", "StealthSession"),
    "HeaderSpoofer": ("osint.header_spoofer", "HeaderSpoofer"),
    "BrowserProfile": ("osint.header_spoofer", "BrowserProfile"),
    "ChallengeDetector": ("osint.challenge_detector", "ChallengeDetector"),
    "ChallengeDetected": ("osint.challenge_detector", "ChallengeDetected"),
    # -- live --
    "live_intel": ("osint.live", "live_intel"),
    "format_live": ("osint.live", "format_live"),
    "diff_live": ("osint.live", "diff_live"),
    "run_live": ("osint.live", "run_live"),
    "render_live": ("osint.viz", "render_live"),
    "LiveIntelResult": ("osint.live", "LiveIntelResult"),
    "FlightState": ("osint.live", "FlightState"),
    "Earthquake": ("osint.live", "Earthquake"),
    "EonetEvent": ("osint.live", "EonetEvent"),
    "MalwareC2": ("osint.live", "MalwareC2"),
    "SpaceWeather": ("osint.live", "SpaceWeather"),
    "SatelliteTle": ("osint.live", "SatelliteTle"),
}

__all__ = [
    "email_lookup", "EmailIntelResult", "EmailFormat",
    "username_search", "UsernameSearchResult", "PlatformResult",
    "domain_intel", "DomainIntelResult", "WhoisInfo",
    "social_lookup", "SocialIntelResult", "GitHubUser",
    "breach_check", "BreachCheckResult", "BreachInfo",
    "run_osint", "OsintResult",
    "generate_report",
    "OsintArtifact", "OsintGraph", "normalize", "synonym_key",
    "collect", "list_sources",
    "expand_graph", "render_graph",
    "run_agent", "OsintAgentResult", "verify_claims",
    "identity_profile", "IdentityProfile",
    "StealthSession", "HeaderSpoofer", "BrowserProfile", "ChallengeDetector", "ChallengeDetected",
    "live_intel", "format_live", "diff_live", "run_live", "render_live", "LiveIntelResult",
    "FlightState", "Earthquake", "EonetEvent", "MalwareC2",
    "SpaceWeather", "SatelliteTle",
]


def __getattr__(name):
    """Lazy-load symbols from their source submodules on first access."""
    if name in _SYMBOL_MAP:
        mod_path, orig_name = _SYMBOL_MAP[name]
        mod = importlib.import_module(mod_path)
        attr = getattr(mod, orig_name)
        globals()[name] = attr
        return attr
    raise AttributeError(f"module 'osint' has no attribute {name!r}")
