(function defineApi() {
  function csrfToken() {
    return document.cookie
      .split(";")
      .map(cookie => cookie.trim())
      .find(cookie => cookie.startsWith("manfordCsrf="))
      ?.split("=")
      .slice(1)
      .join("=") || "";
  }

  async function request(url, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      "X-CSRF-Token": decodeURIComponent(csrfToken()),
      ...(options.headers || {})
    };
    const response = await fetch(url, { ...options, headers });
    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }
    if (!response.ok) {
      throw new Error(data.error || "Operation impossible.");
    }
    return data;
  }

  window.DDApi = Object.freeze({ csrfToken, request });
})();
