class AuditGuard {
  constructor(apiUrl = 'https://auditguard-aaas.onrender.com', apiKey = undefined) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  async scan(prompt) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    const response = await fetch(`${this.apiUrl}/v1/scan`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ prompt }),
    });
    if (!response.ok) throw new Error(`AuditGuard HTTP ${response.status}: ${await response.text()}`);
    return response.json();
  }

  async protect(prompt) {
    const result = await this.scan(prompt);
    return { cleanPrompt: result.clean_prompt, isSafe: !result.is_threat };
  }
}

module.exports = { AuditGuard };
