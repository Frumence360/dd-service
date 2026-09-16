(function defineCharts() {
  function createStockChart(element) {
    if (!window.Chart || !element) {
      return {
        data: { labels: [], datasets: [{ data: [] }] },
        update() {}
      };
    }

    return new Chart(element, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Quantite disponible",
          data: [],
          backgroundColor: "#1f6feb"
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
      }
    });
  }

  window.DDCharts = Object.freeze({ createStockChart });
})();
