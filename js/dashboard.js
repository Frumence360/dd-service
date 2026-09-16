const STORAGE_KEY = "manfordStockDB";
    const HISTORY_KEY = "manfordStockHistory";
    const products = {};
    const history = [];
    let editingProduct = null;
    let activeMovementButton = null;
    let currentRole = null;
    let currentCompanyId = null;
    let companies = [];
    let users = [];
    let directoryUsers = [];
    let members = [];
    let editingUser = null;

    let currencyCode = "USD";
    let currency = new Intl.NumberFormat("fr-FR", {
      style: "currency",
      currency: currencyCode,
      maximumFractionDigits: 2
    });

    const stockChart = window.DDCharts.createStockChart(
      document.getElementById("stockChart")
    );

    async function loadData() {
      const sessionResponse = await fetch("/api/session");
      const session = await sessionResponse.json();

      if (!session.authenticated) {
        window.location.href = "connexion.html";
        return;
      }

      currentRole = session.role;
      currentCompanyId = session.companyId;

      const companiesResponse = await fetch("/api/companies");
      if (companiesResponse.status === 401) {
        window.location.href = "connexion.html";
        return;
      }
      if (!companiesResponse.ok) {
        throw new Error("Impossible de charger les entreprises.");
      }

      const companyData = await companiesResponse.json();
      companies = Array.isArray(companyData.companies) ? companyData.companies : [];
      currentCompanyId = companyData.activeCompanyId || currentCompanyId;
      renderCompanySelector();
      await loadCompanySettings();

      const response = await fetch("/api/stock");
      if (response.status === 401) {
        window.location.href = "connexion.html";
        return;
      }

      if (!response.ok) {
        throw new Error("Impossible de charger les donnees du serveur.");
      }

      const data = await response.json();
      Object.assign(products, data.products || {});
      history.splice(0, history.length, ...(Array.isArray(data.history) ? data.history : []));
    }

    function renderCompanySelector() {
      const select = document.getElementById("companySelect");
      select.replaceChildren();
      companies.forEach(company => {
        const option = document.createElement("option");
        option.value = company.id || "";
        option.textContent = company.name;
        option.selected = String(company.id) === String(currentCompanyId)
          || (!company.id && !currentCompanyId);
        select.appendChild(option);
      });
      select.disabled = companies.length <= 1;
    }

    async function changeCompany(event) {
      const companyId = event.currentTarget.value;
      if (!companyId || String(companyId) === String(currentCompanyId)) return;

      event.currentTarget.disabled = true;
      try {
        const response = await fetch("/api/session/company", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": decodeURIComponent(csrfToken())
          },
          body: JSON.stringify({ companyId })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Changement d'entreprise impossible.");
        window.location.reload();
      } catch (error) {
        document.getElementById("formMessage").textContent = error.message;
        event.currentTarget.disabled = false;
        renderCompanySelector();
      }
    }

    function canManageUsers() {
      return currentRole === "admin";
    }

    function canWriteStock() {
      return ["admin", "magasinier"].includes(currentRole);
    }

    function canDeleteProduct() {
      return currentRole === "admin";
    }

    function applyCompanyCurrency(code) {
      currencyCode = code || "USD";
      currency = new Intl.NumberFormat("fr-FR", {
        style: "currency",
        currency: currencyCode,
        maximumFractionDigits: 2
      });
      document.querySelector('label[for="unitPrice"]').textContent = `Prix unitaire ${currencyCode}`;
    }

    async function loadCompanySettings() {
      const response = await fetch("/api/company/settings");
      if (!response.ok) throw new Error("Impossible de charger les parametres de l'entreprise.");
      const data = await response.json();
      const company = data.company;
      applyCompanyCurrency(company.currency);
      document.querySelector(".brand-logo").src = company.logoUrl || "image/logos.jpg";
      document.querySelector(".brand-logo").alt = company.name;
      document.getElementById("threshold").value = company.defaultThreshold;
      document.getElementById("settingsCompanyName").value = company.name;
      document.getElementById("companyAddress").value = company.address || "";
      document.getElementById("companyPhone").value = company.phone || "";
      document.getElementById("companyLogoUrl").value = company.logoUrl || "";
      document.getElementById("companyCurrency").value = company.currency;
      document.getElementById("companyThreshold").value = company.defaultThreshold;
      document.getElementById("companySettings").classList.toggle("hidden", !canManageUsers());
    }

    async function loadAuditLogs() {
      const section = document.getElementById("auditManagement");
      section.classList.toggle("hidden", !canManageUsers());
      if (!canManageUsers()) return;
      const response = await fetch("/api/audit");
      if (!response.ok) throw new Error("Impossible de charger le journal d'audit.");
      const data = await response.json();
      const body = document.getElementById("auditBody");
      body.replaceChildren();
      data.logs.forEach(log => {
        const row = document.createElement("tr");
        const values = [
          new Date(log.createdAt).toLocaleString("fr-FR"),
          log.actor,
          log.action,
          `${log.entityType}${log.entityId ? ` #${log.entityId}` : ""}`,
          JSON.stringify(log.metadata)
        ];
        values.forEach(value => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });
        body.appendChild(row);
      });
      if (data.logs.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty-state";
        cell.textContent = "Aucune action enregistree.";
        row.appendChild(cell);
        body.appendChild(row);
      }

      async function loadBilling() {
        const section = document.getElementById("billingManagement");
        section.classList.toggle("hidden", !canManageUsers());
        if (!canManageUsers()) return;
        const response = await fetch("/api/billing");
        if (!response.ok) throw new Error("Impossible de charger l'abonnement.");
        const data = await response.json();
        document.getElementById("billingPlan").value = data.subscription.plan;
        document.getElementById("billingStatus").textContent =
          `${data.subscription.status} - jusqu'au ${new Date(data.subscription.currentPeriodEnd).toLocaleDateString("fr-FR")}`;
      }

      async function saveBilling(event) {
        event.preventDefault();
        const message = document.getElementById("billingMessage");
        try {
          const response = await userRequest("/api/billing", {
            method: "PUT",
            body: JSON.stringify({ plan: document.getElementById("billingPlan").value })
          });
          message.textContent = `Plan ${response.subscription.plan} enregistre.`;
          await loadBilling();
        } catch (error) {
          message.textContent = error.message;
        }
      }

      async function createInvitation(event) {
        event.preventDefault();
        const message = document.getElementById("invitationMessage");
        try {
          const form = event.currentTarget;
          const data = await userRequest(`/api/companies/${encodeURIComponent(currentCompanyId)}/invitations`, {
            method: "POST",
            body: JSON.stringify(Object.fromEntries(new FormData(form).entries()))
          });
          message.textContent = `Invitation generee. Token a transmettre : ${data.token}`;
          form.reset();
        } catch (error) {
          message.textContent = error.message;
        }
      }

      function downloadReport(name, rows) {
        const csv = rows.map(row => row.map(value => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
        const link = document.createElement("a");
        link.href = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" }));
        link.download = `${name}-${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        URL.revokeObjectURL(link.href);
      }

      async function exportReport(type) {
        const message = document.getElementById("reportMessage");
        try {
          const response = await fetch(`/api/reports/${encodeURIComponent(type)}`);
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || "Rapport indisponible.");
          if (type === "inventory" || type === "low-stock" || type === "stock-value") {
            downloadReport(type, [
              ["Produit", "Categorie", "Stock", "Seuil", "Prix unitaire", "Valeur"],
              ...data.products.map(product => [
                product.name, product.category, product.quantity, product.threshold,
                product.unitPrice, product.quantity * product.unitPrice
              ])
            ]);
            message.textContent = type === "stock-value"
              ? `Valeur totale : ${currency.format(data.total)}.`
              : "Rapport exporte.";
            return;
          }
          downloadReport("mouvements", [
            ["Date", "Produit", "Type", "Quantite", "Restant", "Observation"],
            ...data.history.map(item => [
              new Date(item.date).toLocaleString("fr-FR"),
              item.product, item.type, item.quantity, item.remaining, item.note
            ])
          ]);
          message.textContent = "Rapport exporte.";
        } catch (error) {
          message.textContent = error.message;
        }
      }
    }

    async function saveCompanySettings(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const message = document.getElementById("companySettingsMessage");
      const body = Object.fromEntries(new FormData(form).entries());
      body.defaultThreshold = Number(body.defaultThreshold);
      try {
        const response = await fetch("/api/company/settings", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": decodeURIComponent(csrfToken())
          },
          body: JSON.stringify(body)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Enregistrement impossible.");
        applyCompanyCurrency(data.company.currency);
        companies = companies.map(company => String(company.id) === String(data.company.id)
          ? { ...company, ...data.company }
          : company);
        renderCompanySelector();
        message.textContent = "Parametres enregistres.";
      } catch (error) {
        message.textContent = error.message;
      }
    }

    function applyRoleUI() {
      const readOnly = !canWriteStock();
      const form = document.getElementById("productForm");
      const message = document.getElementById("formMessage");

      form.querySelectorAll("input, select, textarea, button").forEach(control => {
        control.disabled = readOnly;
      });

      document.getElementById("seedButton").disabled = readOnly;

      if (readOnly) {
        message.textContent = "Acces lecture seule: les modifications sont desactivees.";
      }
    }

    function csrfToken() {
      return window.DDApi.csrfToken();
    }

    async function userRequest(url, options = {}) {
      return window.DDApi.request(url, options);
    }

    function roleLabel(role) {
      return {
        admin: "Administrateur",
        magasinier: "Magasinier",
        lecture: "Lecture seule"
      }[role] || role;
    }

    function renderUsers() {
      const body = document.getElementById("usersBody");
      body.replaceChildren();

      if (users.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty-state";
        cell.textContent = "Aucun compte persistant.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
      }

      users.forEach(user => {
        const row = document.createElement("tr");
        [user.username, roleLabel(user.role), user.active ? "Actif" : "Desactive",
          new Date(user.updatedAt).toLocaleString("fr-FR")].forEach(value => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });

        const actionCell = document.createElement("td");
        const editButton = document.createElement("button");
        editButton.className = "table-action";
        editButton.type = "button";
        editButton.textContent = "Modifier";
        editButton.addEventListener("click", () => startUserEdit(user));

        const toggleButton = document.createElement("button");
        toggleButton.className = "table-action";
        toggleButton.type = "button";
        toggleButton.textContent = user.active ? "Desactiver" : "Activer";
        toggleButton.addEventListener("click", () => toggleUser(user));

        const deleteButton = document.createElement("button");
        deleteButton.className = "table-action danger-text";
        deleteButton.type = "button";
        deleteButton.textContent = "Supprimer";
        deleteButton.addEventListener("click", () => deleteUser(user));
        actionCell.append(editButton, toggleButton, deleteButton);
        row.appendChild(actionCell);
        body.appendChild(row);
      });
    }

    async function loadUsers() {
      if (!canManageUsers()) return;

      const section = document.getElementById("userManagement");
      section.classList.remove("hidden");
      try {
        const data = await userRequest("/api/users", { method: "GET" });
        users = Array.isArray(data.users) ? data.users : [];
        directoryUsers = Array.isArray(data.directory) ? data.directory : users;
        renderUsers();
      } catch (error) {
        document.getElementById("userFormMessage").textContent = error.message;
      }
    }

    function renderMemberUsers() {
      const select = document.getElementById("memberUser");
      select.replaceChildren();
      directoryUsers.forEach(user => {
        const option = document.createElement("option");
        option.value = user.id;
        option.textContent = `${user.username} (${roleLabel(user.role)})`;
        select.appendChild(option);
      });
      select.disabled = users.length === 0;
    }

    function renderMembers() {
      const body = document.getElementById("membersBody");
      body.replaceChildren();
      if (members.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 4;
        cell.className = "empty-state";
        cell.textContent = "Aucun compte rattaché à cette entreprise.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
      }
      members.forEach(member => {
        const row = document.createElement("tr");
        [member.username, roleLabel(member.role), member.active ? "Actif" : "Désactivé"]
          .forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
          });
        const actions = document.createElement("td");
        const toggle = document.createElement("button");
        toggle.className = "table-action";
        toggle.type = "button";
        toggle.textContent = member.active ? "Désactiver" : "Activer";
        toggle.addEventListener("click", () => toggleMember(member));
        const remove = document.createElement("button");
        remove.className = "table-action danger-text";
        remove.type = "button";
        remove.textContent = "Retirer";
        remove.addEventListener("click", () => removeMember(member));
        actions.append(toggle, remove);
        row.appendChild(actions);
        body.appendChild(row);
      });
    }

    async function loadCompanyMembers() {
      if (!canManageUsers() || !currentCompanyId) return;
      const section = document.getElementById("companyManagement");
      section.classList.remove("hidden");
      renderMemberUsers();
      try {
        const data = await userRequest(`/api/companies/${encodeURIComponent(currentCompanyId)}/members`);
        members = Array.isArray(data.members) ? data.members : [];
        renderMembers();
      } catch (error) {
        document.getElementById("memberFormMessage").textContent = error.message;
      }
    }

    async function handleCompanySubmit(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const message = document.getElementById("companyFormMessage");
      try {
        const data = await userRequest("/api/companies", {
          method: "POST",
          body: JSON.stringify({
            name: form.elements.name.value,
            slug: form.elements.slug.value
          })
        });
        companies.push(data.company);
        companies.sort((a, b) => a.name.localeCompare(b.name));
        renderCompanySelector();
        form.reset();
        message.textContent = "Entreprise créée. Changez d'espace depuis le sélecteur.";
      } catch (error) {
        message.textContent = error.message;
      }
    }

    async function handleMemberSubmit(event) {
      event.preventDefault();
      if (!currentCompanyId) return;
      const form = event.currentTarget;
      try {
        const data = await userRequest(
          `/api/companies/${encodeURIComponent(currentCompanyId)}/members`,
          {
            method: "POST",
            body: JSON.stringify({
              userId: form.elements.userId.value,
              role: form.elements.role.value
            })
          }
        );
        members = Array.isArray(data.members) ? data.members : [];
        renderMembers();
        document.getElementById("memberFormMessage").textContent = "Compte rattaché.";
      } catch (error) {
        document.getElementById("memberFormMessage").textContent = error.message;
      }
    }

    async function toggleMember(member) {
      try {
        const data = await userRequest(
          `/api/companies/${encodeURIComponent(currentCompanyId)}/members/${encodeURIComponent(member.id)}`,
          {
            method: "PATCH",
            body: JSON.stringify({ active: !member.active })
          }
        );
        members = Array.isArray(data.members) ? data.members : [];
        renderMembers();
      } catch (error) {
        document.getElementById("memberFormMessage").textContent = error.message;
      }
    }

    async function removeMember(member) {
      if (!confirm(`Retirer "${member.username}" de cette entreprise ?`)) return;
      try {
        await userRequest(
          `/api/companies/${encodeURIComponent(currentCompanyId)}/members/${encodeURIComponent(member.id)}`,
          { method: "DELETE" }
        );
        members = members.filter(item => item.id !== member.id);
        renderMembers();
      } catch (error) {
        document.getElementById("memberFormMessage").textContent = error.message;
      }
    }

    async function handleUserSubmit(event) {
      event.preventDefault();
      if (!canManageUsers()) return;

      const form = event.currentTarget;
      const username = form.elements.username.value.trim().replace(/\s+/g, " ");
      const role = form.elements.role.value;
      const password = form.elements.password.value;
      const message = document.getElementById("userFormMessage");
      if (username.length < 3 || username.length > 80 ||
          (!editingUser && (password.length < 8 || password.length > 128)) ||
          (editingUser && password && (password.length < 8 || password.length > 128))) {
        message.textContent = editingUser
          ? "Identifiant: 3 a 80 caracteres. Mot de passe: 8 a 128 caracteres s'il est modifie."
          : "Identifiant: 3 a 80 caracteres. Mot de passe: 8 a 128 caracteres.";
        return;
      }

      const submitButton = event.submitter;
      setButtonWorking(submitButton, true);
      try {
        const wasEditing = Boolean(editingUser);
        const body = { username, role };
        if (password) body.password = password;
        const data = await userRequest(
          editingUser ? `/api/users/${encodeURIComponent(editingUser.id)}` : "/api/users",
          {
            method: editingUser ? "PATCH" : "POST",
            body: JSON.stringify(editingUser ? body : { ...body, password })
          }
        );
        if (wasEditing) {
          users = users.map(item => item.id === editingUser.id ? data.user : item);
        } else {
          users.push(data.user);
        }
        users.sort((a, b) => a.username.localeCompare(b.username));
        renderUsers();
        resetUserForm();
        message.textContent = wasEditing ? "Compte modifie avec succes." : "Compte cree avec succes.";
      } catch (error) {
        message.textContent = error.message;
      } finally {
        setButtonWorking(submitButton, false);
      }
    }

    function startUserEdit(user) {
      editingUser = user;
      const form = document.getElementById("userForm");
      form.elements.username.value = user.username;
      form.elements.role.value = user.role;
      form.elements.password.value = "";
      document.getElementById("userFormTitle").textContent = "Modifier le compte";
      document.getElementById("userSubmitButton").textContent = "Enregistrer les modifications";
      document.getElementById("cancelUserEditButton").classList.remove("hidden");
      document.getElementById("userFormMessage").textContent = "";
      document.getElementById("userUsername").focus();
    }

    function resetUserForm() {
      editingUser = null;
      document.getElementById("userForm").reset();
      document.getElementById("userFormTitle").textContent = "Creer un compte";
      document.getElementById("userSubmitButton").textContent = "Creer le compte";
      document.getElementById("cancelUserEditButton").classList.add("hidden");
    }

    async function toggleUser(user) {
      if (!confirm(`${user.active ? "Desactiver" : "Activer"} le compte "${user.username}" ?`)) return;

      try {
        const data = await userRequest(`/api/users/${encodeURIComponent(user.id)}`, {
          method: "PATCH",
          body: JSON.stringify({ active: !user.active })
        });
        users = users.map(item => item.id === user.id ? data.user : item);
        renderUsers();
        document.getElementById("userFormMessage").textContent = "Etat du compte mis a jour.";
      } catch (error) {
        document.getElementById("userFormMessage").textContent = error.message;
      }
    }

    async function deleteUser(user) {
      if (!confirm(`Supprimer definitivement le compte "${user.username}" ?`)) return;

      try {
        await userRequest(`/api/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
        users = users.filter(item => item.id !== user.id);
        renderUsers();
        document.getElementById("userFormMessage").textContent = "Compte supprime.";
      } catch (error) {
        document.getElementById("userFormMessage").textContent = error.message;
      }
    }

    async function saveData() {
      const response = await fetch("/api/stock", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": decodeURIComponent(csrfToken())
        },
        body: JSON.stringify({ products, history })
      });

      if (response.status === 401) {
        window.location.href = "connexion.html";
        return false;
      }

      if (!response.ok) {
        document.getElementById("formMessage").textContent = "Enregistrement serveur impossible.";
        return false;
      }

      return true;
    }

    function normalizeName(value) {
      return value.trim().replace(/\s+/g, " ");
    }

    function productKey(value) {
      return normalizeName(value)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLocaleLowerCase("fr-FR");
    }

    function normalizeStoredProducts() {
      const normalizedProducts = {};

      Object.values(products).forEach(product => {
        const name = normalizeName(product.name || "");
        if (!name) return;

        const key = productKey(name);
        const normalizedProduct = {
          ...product,
          name,
          quantity: Number(product.quantity) || 0,
          threshold: Number(product.threshold) || 0,
          unitPrice: Number(product.unitPrice) || 0
        };

        if (normalizedProducts[key]) {
          normalizedProducts[key].quantity += normalizedProduct.quantity;
          normalizedProducts[key].threshold = Math.max(
            normalizedProducts[key].threshold,
            normalizedProduct.threshold
          );
          normalizedProducts[key].unitPrice = normalizedProducts[key].unitPrice || normalizedProduct.unitPrice;
          normalizedProducts[key].updatedAt = normalizedProduct.updatedAt || normalizedProducts[key].updatedAt;
          return;
        }

        normalizedProducts[key] = normalizedProduct;
      });

      Object.keys(products).forEach(key => delete products[key]);
      Object.assign(products, normalizedProducts);
    }

    function migrateLocalData() {
      const legacyData = JSON.parse(localStorage.getItem("stockDB") || "{}");
      const localProducts = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      const localHistory = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");

      Object.entries(legacyData).forEach(([name, value]) => {
        const key = productKey(name);
        if (!products[key]) {
          products[key] = {
            name: normalizeName(name),
            category: "Autre",
            quantity: Number(value.stock) || 0,
            threshold: 10,
            unitPrice: 0,
            updatedAt: new Date().toISOString()
          };
        }
      });

      Object.values(localProducts).forEach(product => {
        const key = productKey(product.name || "");
        if (key && !products[key]) {
          products[key] = product;
        }
      });

      if (history.length === 0 && Array.isArray(localHistory)) {
        history.push(...localHistory);
      }
    }

    function productStatus(product) {
      if (product.quantity <= 0) return "Rupture";
      if (product.quantity <= product.threshold) return "Stock bas";
      return "Disponible";
    }

    function statusClass(product) {
      if (product.quantity <= 0) return "status danger";
      if (product.quantity <= product.threshold) return "status warning";
      return "status success";
    }

    function addHistory(product, movement, quantity, note) {
      history.push({
        date: new Date().toISOString(),
        product: product.name,
        type: movement === "in" ? "Entree" : "Sortie",
        quantity,
        remaining: product.quantity,
        note
      });

      if (history.length > 200) {
        history.splice(0, history.length - 200);
      }
    }

    function setButtonWorking(button, isWorking) {
      window.DDUI.setButtonWorking(button, isWorking);
    }

    function setActiveMovementButton(button) {
      if (activeMovementButton && activeMovementButton !== button) {
        activeMovementButton.classList.remove("is-active");
      }

      activeMovementButton = button;
      if (activeMovementButton) {
        activeMovementButton.classList.add("is-active");
      }
    }

    function flashButton(button) {
      window.DDUI.flashButton(button);
    }

    function renderMetrics(list) {
      const allProducts = Object.values(products);
      const totalQuantity = allProducts.reduce((sum, item) => sum + item.quantity, 0);
      const value = allProducts.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);
      const alerts = allProducts.filter(item => item.quantity <= item.threshold).length;

      document.getElementById("productCount").textContent = allProducts.length;
      document.getElementById("totalQuantity").textContent = totalQuantity;
      document.getElementById("stockValue").textContent = currency.format(value);
      document.getElementById("alertCount").textContent = alerts;

      stockChart.data.labels = list.map(item => item.name);
      stockChart.data.datasets[0].data = list.map(item => item.quantity);
      stockChart.update();
    }

    function renderInventory() {
      const query = productKey(document.getElementById("searchInput").value);
      const statusFilter = document.getElementById("statusFilter").value;
      const list = Object.values(products)
        .filter(item => (
          productKey(item.name).includes(query) || productKey(item.category).includes(query)
        ) && (statusFilter === "all" || productStatus(item) === statusFilter))
        .sort((a, b) => a.name.localeCompare(b.name));

      const body = document.getElementById("inventoryBody");
      body.replaceChildren();

      if (list.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.className = "empty-state";
        cell.textContent = "Aucun produit enregistre.";
        row.appendChild(cell);
        body.appendChild(row);
      }

      list.forEach(product => {
        const row = document.createElement("tr");
        const values = [
          product.name,
          product.category,
          product.quantity,
          product.threshold,
          currency.format(product.quantity * product.unitPrice)
        ];

        values.forEach(value => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });

        const statusCell = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = statusClass(product);
        badge.textContent = productStatus(product);
        statusCell.appendChild(badge);
        row.appendChild(statusCell);

        const actionCell = document.createElement("td");
        const editButton = document.createElement("button");
        editButton.className = "table-action";
        editButton.type = "button";
        editButton.textContent = "Mouvement";
        editButton.disabled = !canWriteStock();
        editButton.addEventListener("click", () => {
          setActiveMovementButton(editButton);
          startEdit(productKey(product.name));
        });

        const deleteButton = document.createElement("button");
        deleteButton.className = "table-action danger-text";
        deleteButton.type = "button";
        deleteButton.textContent = "Supprimer";
        deleteButton.disabled = !canDeleteProduct();
        deleteButton.addEventListener("click", () => {
          flashButton(deleteButton);
          deleteProduct(productKey(product.name));
        });

        actionCell.append(editButton, deleteButton);
        row.appendChild(actionCell);
        body.appendChild(row);
      });

      renderMetrics(list);
      renderHistory();
    }

    function renderHistory() {
      const body = document.getElementById("historyBody");
      body.replaceChildren();

      history.slice(-12).reverse().forEach(item => {
        const row = document.createElement("tr");
        const date = new Date(item.date).toLocaleString("fr-FR");
        [date, item.product, item.type, item.quantity, item.remaining].forEach(value => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });
        body.appendChild(row);
      });

      if (history.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty-state";
        cell.textContent = "Aucun mouvement pour le moment.";
        row.appendChild(cell);
        body.appendChild(row);
      }
    }

    function resetForm() {
      editingProduct = null;
      setActiveMovementButton(null);
      document.getElementById("productForm").reset();
      document.getElementById("threshold").value = 10;
      document.getElementById("unitPrice").value = 0;
      document.getElementById("formTitle").textContent = "Enregistrer un mouvement";
      document.getElementById("cancelEditButton").classList.add("hidden");
      document.getElementById("formMessage").textContent = "";
      document.getElementById("name").disabled = false;
    }

    function startEdit(key) {
      const product = products[key];
      if (!product) return;

      editingProduct = key;
      document.getElementById("name").value = product.name;
      document.getElementById("name").disabled = true;
      document.getElementById("category").value = product.category;
      document.getElementById("movement").value = "in";
      document.getElementById("quantity").value = 1;
      document.getElementById("threshold").value = product.threshold;
      document.getElementById("unitPrice").value = product.unitPrice;
      document.getElementById("note").value = "Ajustement manuel";
      document.getElementById("formTitle").textContent = "Mouvement sur produit";
      document.getElementById("cancelEditButton").classList.remove("hidden");
    }

    async function deleteProduct(key) {
      if (!canDeleteProduct()) return;

      const product = products[key];
      if (!product) return;

      const confirmed = confirm(`Supprimer le produit "${product.name}" de l'inventaire ?`);
      if (!confirmed) return;

      const response = await fetch(`/api/products/${encodeURIComponent(key)}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": decodeURIComponent(csrfToken()) }
      });

      if (!response.ok) {
        document.getElementById("formMessage").textContent = response.status === 403
          ? "Suppression reservee a l'administrateur."
          : "Suppression impossible.";
        return;
      }

      delete products[key];
      addHistory({ name: product.name, quantity: 0 }, "out", 0, "Produit supprime");
      renderInventory();
    }

    async function handleSubmit(event) {
      event.preventDefault();
      if (!canWriteStock()) return;

      const form = event.currentTarget;
      const fields = form.elements;
      const submitButton = event.submitter;
      const name = editingProduct ? products[editingProduct].name : normalizeName(fields.name.value);
      const key = editingProduct || productKey(name);
      const category = fields.category.value;
      const movement = fields.movement.value;
      const quantity = Number(fields.quantity.value);
      const threshold = Number(fields.threshold.value);
      const unitPrice = Number(fields.unitPrice.value);
      const note = fields.note.value.trim();
      const message = document.getElementById("formMessage");

      if (!name || quantity <= 0 || threshold < 0 || unitPrice < 0) {
        message.textContent = "Veuillez verifier les informations saisies.";
        return;
      }

      const product = products[key] || {
        name,
        category,
        quantity: 0,
        threshold,
        unitPrice,
        updatedAt: new Date().toISOString()
      };

      if (movement === "out" && quantity > product.quantity) {
        message.textContent = "La sortie depasse le stock disponible.";
        return;
      }

      product.category = category;
      product.threshold = threshold;
      product.unitPrice = unitPrice;
      product.quantity += movement === "in" ? quantity : -quantity;
      product.updatedAt = new Date().toISOString();
      product.name = name;
      products[key] = product;

      setButtonWorking(submitButton, true);
      addHistory(product, movement, quantity, note);
      try {
        const saved = await saveData();
        if (!saved) return;

        renderInventory();
        resetForm();
        message.textContent = "Mouvement enregistre avec succes.";
      } finally {
        setButtonWorking(submitButton, false);
      }
    }

    function exportCSV() {
      const rows = [
        ["Produit", "Categorie", "Stock", "Seuil", "Prix unitaire", "Valeur", "Statut"]
      ];

      Object.values(products).forEach(product => {
        rows.push([
          product.name,
          product.category,
          product.quantity,
          product.threshold,
          product.unitPrice,
          product.quantity * product.unitPrice,
          productStatus(product)
        ]);
      });

      function escapeCSVValue(value) {
        const text = String(value);
        const safeText = /^[\s]*[=+\-@]/.test(text) ? `'${text}` : text;

        return `"${safeText.replaceAll('"', '""')}"`;
      }

      const csv = rows
        .map(row => row.map(escapeCSVValue).join(","))
        .join("\n");
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "inventaire-manford.csv";
      link.click();
      URL.revokeObjectURL(link.href);
    }

    async function seedExample() {
      if (!canWriteStock()) return;

      const seedButton = document.getElementById("seedButton");
      const examples = [
        { name: "Ciment gris", category: "Materiaux", quantity: 45, threshold: 15, unitPrice: 12 },
        { name: "Casque de protection", category: "Equipement", quantity: 8, threshold: 10, unitPrice: 7.5 },
        { name: "Huile vegetale", category: "Alimentation", quantity: 30, threshold: 12, unitPrice: 4 },
        { name: "Farine de ble", category: "Alimentation", quantity: 60, threshold: 20, unitPrice: 2.2 }
      ];
      let addedCount = 0;

      examples.forEach(item => {
        const key = productKey(item.name);
        if (products[key]) return;

        products[key] = { ...item, updatedAt: new Date().toISOString() };
        addHistory(products[key], "in", item.quantity, "Donnees de demonstration");
        addedCount += 1;
      });

      setButtonWorking(seedButton, true);
      try {
        const saved = await saveData();
        if (!saved) return;

        renderInventory();

        document.getElementById("formMessage").textContent = addedCount > 0
          ? `${addedCount} produit(s) de demonstration ajoute(s).`
          : "Les donnees de demonstration sont deja chargees.";
      } finally {
        setButtonWorking(seedButton, false);
      }
    }

    async function init() {
      await loadData();
      migrateLocalData();
      normalizeStoredProducts();
      await saveData();
      renderInventory();
      applyRoleUI();

      document.getElementById("productForm").addEventListener("submit", handleSubmit);
      document.getElementById("searchInput").addEventListener("input", renderInventory);
      document.getElementById("statusFilter").addEventListener("change", renderInventory);
      document.getElementById("exportButton").addEventListener("click", event => {
        flashButton(event.currentTarget);
        exportCSV();
      });
      document.getElementById("seedButton").addEventListener("click", seedExample);
      document.getElementById("cancelEditButton").addEventListener("click", resetForm);
      document.getElementById("companySelect").addEventListener("change", changeCompany);
      document.getElementById("userForm").addEventListener("submit", handleUserSubmit);
      document.getElementById("cancelUserEditButton").addEventListener("click", resetUserForm);
      document.getElementById("companyForm").addEventListener("submit", handleCompanySubmit);
      document.getElementById("memberForm").addEventListener("submit", handleMemberSubmit);
      document.getElementById("companySettingsForm").addEventListener("submit", saveCompanySettings);
      document.getElementById("refreshAuditButton").addEventListener("click", loadAuditLogs);
      document.getElementById("billingForm").addEventListener("submit", saveBilling);
      document.getElementById("invitationForm").addEventListener("submit", createInvitation);
      document.querySelectorAll(".report-button").forEach(button => {
        button.addEventListener("click", () => exportReport(button.dataset.report));
      });
      await loadUsers();
      await loadCompanyMembers();
      await loadAuditLogs();
      await loadBilling();
      document.getElementById("invitationManagement").classList.toggle("hidden", !canManageUsers());
    }

    init().catch(error => {
      document.getElementById("formMessage").textContent = error.message;
    });
  