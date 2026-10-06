/*
 * MFA enrolment screens.
 *
 * Three things happen here that the sign-in page's pi-form.js cannot do:
 *
 *  - the six code boxes are mirrored into the single #otp field the server actually reads;
 *  - the authenticator app's otpauth:// URI is turned into a QR code client-side, from the
 *    vendored qr-code-styling, so the enrolment URI is never rendered as a server-side image;
 *  - the Telegram screen polls the existing bot endpoints and then writes the link itself,
 *    because enrolment is not a broker round trip and so cannot use the IdP's callback.
 *
 * Loaded by edc-mfa-enrol-*.ftl. Each screen only wires up the elements it actually has, so one
 * file serves all three.
 */
(function () {
  "use strict";

  function initCodeBoxes() {
    var boxes = document.getElementById("edc-code-boxes");
    var input = document.getElementById("otp");
    if (!boxes || !input) {
      return;
    }
    var cells = Array.prototype.slice.call(boxes.querySelectorAll(".edc-otp-box"));

    function mirror() {
      input.value = cells.map(function (cell) { return cell.value; }).join("");
    }

    cells.forEach(function (cell, index) {
      cell.addEventListener("input", function () {
        cell.value = cell.value.replace(/\D/g, "").slice(-1);
        mirror();
        if (cell.value && index < cells.length - 1) {
          cells[index + 1].focus();
        }
      });

      cell.addEventListener("keydown", function (event) {
        if (event.key === "Backspace" && !cell.value && index > 0) {
          cells[index - 1].focus();
        } else if (event.key === "ArrowLeft" && index > 0) {
          cells[index - 1].focus();
        } else if (event.key === "ArrowRight" && index < cells.length - 1) {
          cells[index + 1].focus();
        }
      });

      // Pastes of a whole code land in one cell; spread them across the rest.
      cell.addEventListener("paste", function (event) {
        var text = (event.clipboardData || window.clipboardData).getData("text") || "";
        var digits = text.replace(/\D/g, "");
        if (digits.length < 2) {
          return;
        }
        event.preventDefault();
        cells.forEach(function (target, offset) {
          target.value = digits.charAt(offset) || "";
        });
        mirror();
        cells[Math.min(digits.length, cells.length - 1)].focus();
      });
    });

    mirror();
    if (cells.length) {
      cells[0].focus();
    }
  }

  function initTotpQr() {
    var host = document.getElementById("edc-qr");
    if (!host) {
      return;
    }
    var uri = host.getAttribute("data-uri");
    if (!uri) {
      return;
    }
    if (typeof QRCodeStyling === "undefined") {
      // Never fail quietly here. This branch once shipped because the TOTP template never loaded
      // the QR library, and the screen rendered with no code and no explanation at all - the one
      // failure a user cannot diagnose and cannot work around. If the library is missing the
      // secret is still usable, so open that panel rather than leave an empty box.
      showSetupKey(uri);
      var details = host.parentNode.querySelector("details.edc-setup-key");
      if (details) {
        details.open = true;
      }
      return;
    }
    new QRCodeStyling({
      width: 208,
      height: 208,
      type: "svg",
      data: uri,
      dotsOptions: { color: "#000000", type: "rounded" },
      cornersSquareOptions: { type: "extra-rounded" },
      backgroundOptions: { color: "#ffffff" },
      qrOptions: { errorCorrectionLevel: "M" }
    }).append(host);

    // The otpauth URI is useless typed by hand, but the secret inside it is not, so show that for
    // anyone whose camera will not focus on a screen.
    showSetupKey(uri);
  }

  function showSetupKey(uri) {
    var key = document.getElementById("edc-setup-key");
    if (key) {
      var secret = /secret=([^&]+)/.exec(uri);
      key.textContent = secret ? secret[1] : "";
    }
  }

  function initBackupCodes() {
    var button = document.getElementById("edc-codes-download");
    var host = document.getElementById("edc-codes");
    if (!button || !host) {
      return;
    }
    button.addEventListener("click", function () {
      var codes = Array.prototype.slice.call(host.querySelectorAll(".edc-code"))
        .map(function (node) { return node.textContent.trim(); })
        .filter(Boolean);
      if (!codes.length) {
        return;
      }
      var lines = [
        "EDC MFA backup codes",
        "",
        "Each code works once, in place of a verification code.",
        "Signing in again replaces this set: they stop working.",
        ""
      ].concat(codes);
      var blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = (button.getAttribute("data-filename") || "backup-codes") + ".txt";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    });
  }

  function initTelegram() {
    var config = window.edcEnrolTelegram;
    var host = document.getElementById("edc-qr");
    if (!config || !host) {
      return;
    }

    var timer = document.getElementById("edc-telegram-timer");
    var prompt = document.getElementById("edc-phone-prompt");
    var errorBox = document.getElementById("edc-telegram-error");
    var continueButton = document.getElementById("edc-telegram-continue");
    var form = document.getElementById("edc-enrol-form");
    var ticker = null;
    var poller = null;
    var slowHint = null;
    var secondsLeft = 60;
    var checking = false;
    var finished = false;
    var startedAt = 0;

    function showError(node) {
      var host = document.getElementById("edc-enrol-telegram");
      if (!node || !host) {
        return;
      }
      node.hidden = false;
      node.textContent = host.getAttribute("data-failed") || "";
    }

    function stop() {
      window.clearInterval(ticker);
      window.clearInterval(poller);
      window.clearTimeout(slowHint);
      slowHint = null;
    }

    /*
     * If the scan has not registered after a few seconds, say so. Telegram's long polling means
     * a dropped connection costs tens of seconds of silence, and a QR code that simply does
     * nothing reads as "this is broken" rather than "wait".
     */
    function armSlowHint() {
      window.clearTimeout(slowHint);
      slowHint = window.setTimeout(function () {
        if (finished || checking) {
          return;
        }
        var node = document.getElementById("edc-slow-hint");
        if (node) {
          node.hidden = false;
        }
      }, 8000);
    }

    function fail(error) {
      stop();
      // Logged as well as shown. A thrown error inside a promise chain used to be swallowed into a
      // small note at the bottom of the page, which is indistinguishable from "the bot is broken".
      if (error) {
        window.console && window.console.error("EDC enrolment:", error);
      }
      showError(errorBox);
    }

    function finish() {
      if (finished) {
        return;
      }
      finished = true;
      stop();
      if (continueButton) {
        continueButton.disabled = false;
        continueButton.hidden = false;
      }
      // Submitting rather than navigating is what hands control back to the required action, which
      // re-reads the channel the link endpoint has just written.
      if (form) {
        form.submit();
      }
    }

    function setTimer(left) {
      if (!timer) {
        return;
      }
      var minutes = Math.floor(Math.max(left, 0) / 60);
      var seconds = Math.max(left, 0) % 60;
      timer.textContent = minutes + ":" + (seconds < 10 ? "0" + seconds : seconds);
    }

    ticker = window.setInterval(function () {
      secondsLeft -= 1;
      setTimer(secondsLeft);
      if (secondsLeft <= 0) {
        // The bot's AuthState expires with it, so a new code has to be minted rather than waited
        // out. Stop polling first: the old state id is gone and its status will never change.
        stop();
        renderQr();
        if (prompt) {
          prompt.hidden = true;
        }
      }
    }, 1000);

    poller = window.setInterval(check, 3000);

    function check() {
      if (checking || finished || secondsLeft <= 0) {
        return;
      }
      checking = true;
      fetch(config.statusUrl)
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (data) {
          if (!data) {
            return;
          }
          if (data.status === "COMPLETED") {
            return link();
          }
          if (data.status === "BOT_STARTED") {
            window.clearTimeout(slowHint);
            var hide = document.getElementById("edc-slow-hint");
            if (hide) {
              hide.hidden = true;
            }
          }
          if (data.status === "BOT_STARTED" && prompt && prompt.hidden) {
            return requestPhone();
          }
        })
        .catch(function () {
          // Transient: the poll runs again shortly.
        })
        .finally(function () {
          checking = false;
        });
    }

    function requestPhone() {
      return fetch(config.phoneUrl)
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (data) {
          if (!data || !prompt) {
            return;
          }
          if (data.phoneRequired) {
            prompt.hidden = false;
          } else if (data.scanned) {
            // The bot knows the scan but there is nothing left to ask for - linking is done, or
            // was refused elsewhere. Say so rather than leaving the user staring at a QR code.
            stop();
            finish();
          }
        })
        .catch(function () { /* retried on the next tick */ });
    }

    function link() {
      return fetch(config.linkUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      }).then(function (response) {
        if (!response.ok) {
          throw new Error("link failed: " + response.status);
        }
        finish();
      }).catch(function () {
        fail();
      });
    }

    function renderQr() {
      secondsLeft = 60;
      setTimer(secondsLeft);
      host.innerHTML = "";
      return fetch(config.qrUrl)
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (data) {
          if (!data || !data.deepLink) {
            throw new Error("no deeplink in the response");
          }
          var link = document.getElementById("edc-telegram-link");
          if (link) {
            link.href = data.deepLink;
          }
          new QRCodeStyling({
            width: 208,
            height: 208,
            type: "svg",
            data: data.deepLink,
            image: config.resourcesPath + "/img/telegram.svg",
            dotsOptions: { color: "#000000", type: "rounded" },
            cornersSquareOptions: { type: "extra-rounded" },
            imageOptions: { saveAsBlob: true, imageSize: 0.4, margin: 0 },
            backgroundOptions: { color: "#ffffff" },
            qrOptions: { errorCorrectionLevel: "M" }
          }).append(host);
        })
        .catch(fail);
    }

    // Starting the bot is what makes it answer at all in polling mode; harmless in webhook mode.
    fetch(config.initUrl, { method: "POST" }).catch(function () { /* polling still works */ });
    renderQr();
    armSlowHint();
  }

  function boot() {
    initCodeBoxes();
    initTotpQr();
    initBackupCodes();
    initTelegram();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
