document.getElementById("loginForm").addEventListener("submit", async event => {
  event.preventDefault();

  const identifier = document.getElementById("identifier").value.trim();
  const password = document.getElementById("password").value;
  const message = document.getElementById("message");
  const submitButton = event.currentTarget.querySelector('button[type="submit"]');
  message.textContent = "";
  submitButton.disabled = true;

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password })
    });

    if (response.ok) {
      window.location.href = "stock.html";
      return;
    }

    const data = await response.json();
    if (response.status === 401) {
      message.textContent = `Mot de passe incorrect. Tentatives restantes: ${data.remainingAttempts}.`;
    } else if (response.status === 429) {
      const minutes = Math.ceil((data.retryAfter || 0) / 60);
      message.textContent = `Trop de tentatives. Reessaie dans ${minutes} minute(s).`;
    } else if (response.status === 500) {
      message.textContent = data.error || "Configuration serveur incomplete.";
    } else if (response.status === 400) {
      message.textContent = data.error || "Identifiant ou mot de passe invalide.";
    } else {
      message.textContent = "Ouvre l'application avec le lanceur HTTPS.";
    }
  } catch {
    message.textContent = "Serveur indisponible. Lance le serveur puis ouvre l'adresse HTTPS affichee.";
  } finally {
    submitButton.disabled = false;
  }
});
