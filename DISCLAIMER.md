# Disclaimer

phishing-header-analyzer is a defensive triage aid. Its findings and risk score are indicators to support an analyst's judgment, not a verdict. A low score does not prove a message is safe, and a high score does not prove it is malicious.

Header data can be forged by the sender up to the point where a trusted mail server receives the message. Treat any header added before your own organization's mail gateway as attacker-controllable.

Only analyze messages you are authorized to handle. Email headers can contain personal data such as names, email addresses, and IP addresses; handle reports according to your organization's data handling policies.

This software is provided "as is," without warranty of any kind. See [LICENSE](LICENSE).
