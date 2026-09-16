(function initializeNavigation() {
  const links = [...document.querySelectorAll(".sidebar-link, .main-nav a[href]")];
  const hashLinks = links.filter(link => link.getAttribute("href").startsWith("#"));
  const sections = hashLinks
    .map(link => document.querySelector(link.getAttribute("href")))
    .filter(Boolean);

  function setActive(link) {
    links.forEach(item => {
      item.classList.toggle("is-active", item === link);
      if (item === link) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
  }

  function updateActiveLink() {
    if (sections.length === 0) {
      const currentHash = window.location.hash;
      const currentPage = window.location.pathname.split("/").pop() || "index.html";
      const current = links.find(link => {
        const href = link.getAttribute("href");
        return href === currentHash
          || (href === "index.html" && !currentHash)
          || href === currentPage;
      });
      if (current) setActive(current);
      return;
    }

    if (window.location.hash) {
      const hashLink = hashLinks.find(link => link.getAttribute("href") === window.location.hash);
      if (hashLink) {
        setActive(hashLink);
        return;
      }
    }

    if (sections[0].getBoundingClientRect().top > 140) {
      const homeLink = links.find(link => link.getAttribute("href") === "index.html");
      if (homeLink) {
        setActive(homeLink);
        return;
      }
    }

    const current = sections.reduce((active, section) => {
      if (section.getBoundingClientRect().top <= 140) return section;
      return active;
    }, sections[0]);

    const currentLink = hashLinks.find(link => link.getAttribute("href") === `#${current.id}`);
    if (currentLink) setActive(currentLink);
  }

  links.forEach(link => {
    link.addEventListener("click", () => setActive(link));
  });
  window.addEventListener("scroll", updateActiveLink, { passive: true });
  updateActiveLink();
})();
