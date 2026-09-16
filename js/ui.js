(function defineUi() {
  function setButtonWorking(button, isWorking) {
    if (!button) return;
    button.classList.toggle("is-active", isWorking);
    button.disabled = isWorking;
  }

  function flashButton(button) {
    if (!button) return;
    button.classList.add("is-active");
    window.setTimeout(() => button.classList.remove("is-active"), 450);
  }

  window.DDUI = Object.freeze({ setButtonWorking, flashButton });
})();
