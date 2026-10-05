(function () {
  "use strict";

  function lock(button) {
    if (!button || button.dataset.edcBusy === "true") {
      return;
    }
    button.dataset.edcBusy = "true";
    button.disabled = true;
    button.classList.add("is-loading");
  }

  function unlock(button) {
    if (!button) {
      return;
    }
    button.disabled = false;
    button.classList.remove("is-loading");
    delete button.dataset.edcBusy;
  }

  /**
   * Locks a #kc-login submit button while its form posts, so the page shows the same busy state
   * wherever that button is used.
   *
   * Attaches to whichever form owns the button rather than to a fixed form id, because the
   * sign-in, forgot-password and update-password pages all use #kc-login but have their own form
   * ids.
   *
   * Locking happens only on the submit event. Disabling the button from a click or keydown handler
   * runs before the browser decides to submit, which cancels the submission entirely; the submit
   * event covers both a button click and Enter in a text field.
   */
  function init() {
    var button = document.getElementById("kc-login");
    var form = button && button.form;
    if (!form || !button) {
      return;
    }

    form.addEventListener("submit", function () {
      lock(button);
    });

    window.addEventListener("pageshow", function () {
      unlock(button);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();