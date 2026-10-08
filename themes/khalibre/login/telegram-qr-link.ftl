<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false displayMessage=true; section>
  <#if section = "header">
    <#if linkMode>${msg("telegram.link-title")}<#else>${msg("telegram.title")}</#if>
  <#elseif section = "footer">
    <div class="edc-help">${msg("telegram.notLinked")}</div>
  <#elseif section = "form">
    <script src="${url.resourcesPath}/js/qr-code-styling-1.9.2.js"></script>

    <p class="subtitle">
      <#if linkMode>${msg("telegram.link-description")}<#else>${msg("telegram.description")}</#if>
    </p>

    <div id="qr-container"></div>

    <p class="edc-waiting" id="qr-status">
      ${msg("telegram.waiting")} <b id="qr-timer">1:00</b>
    </p>

    <p class="hint" id="qr-hint">
      ${msg("telegram.using-this-device")}
      <a id="qr-link" class="kh-link" href="#" data-url="">${msg("doClickHere")}</a>
    </p>

    <div class="edc-note-info" id="phone-number-prompt" hidden>
      <span>${msg("telegram.phone-number-prompt")}</span>
    </div>

    <button type="button" id="qr-refresh"
            class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} edc-secondary">
      ${msg("telegram.refreshCode")}
    </button>

    <div class="edc-alt-signin">
      <a href="${url.loginUrl}">${msg("telegram.signInInstead")}</a>
    </div>

    <script>
      (function () {
        const duration = 60;
        let winQrLink;
        let interval;
        let checkLinkInterval;
        let qrCode;
        let timeLeft = duration;
        let isRedirecting = false;
        let phoneNumberRequestPending = false;
        let isRefreshing = false;

        const apiBase = "/realms/${realm.name}";
        const providerAlias = "${providerAlias!}";
        const callbackUrl = "${callbackUrl!}";

        function formatCountdown(seconds) {
          const minutes = Math.floor(seconds / 60);
          const secs = String(Math.max(seconds, 0) % 60).padStart(2, "0");
          return minutes + ":" + secs;
        }

        async function checkAuthStatus() {
          if (isRedirecting) return;
          try {
            const response = await fetch(apiBase + "/telegram-auth/status");
            const data = await response.json();
            if (data.status === 'BOT_STARTED') {
              if (phoneNumberRequestPending) return;
              phoneNumberRequestPending = true;

              const phoneResponse = await fetch(
                apiBase + "/telegram-auth/" + providerAlias + "/phone-required"
              );
              if (!phoneResponse.ok) {
                phoneNumberRequestPending = false;
                throw new Error("Failed to check phone number requirement");
              }

              const phoneData = await phoneResponse.json();
              const phoneRequired = phoneData.phoneRequired;
              if (phoneRequired === undefined) {
                phoneNumberRequestPending = false;
                throw new Error("Phone number requirement was not returned");
              }

              if (phoneRequired) {
                const prompt = document.getElementById("phone-number-prompt");
                if (prompt) prompt.hidden = false;
                return;
              }

              phoneNumberRequestPending = false;
              isRedirecting = true;
              clearInterval(interval);
              clearInterval(checkLinkInterval);
              if (winQrLink) winQrLink.close();
              window.location.href = callbackUrl;
              return;
            }

            if (data.status === 'COMPLETED') {
              isRedirecting = true;
              clearInterval(interval);
              clearInterval(checkLinkInterval);
              if (winQrLink) winQrLink.close();
              window.location.href = callbackUrl;
            }
          } catch (e) {
            console.error("Error checking auth status:", e);
          }
        }

        function fetchQRCodeDataAndRender() {
          if (isRefreshing || isRedirecting) return;
          isRefreshing = true;
          fetch(apiBase + "/telegram-auth/" + providerAlias + "/qr")
            .then(function (response) { return response.json(); })
            .then(function (data) {
              const qrLink = document.getElementById("qr-link");
              qrLink.dataset.url = data.deepLink;
              const container = document.getElementById("qr-container");
              container.innerHTML = "";

              qrCode = new QRCodeStyling({
                width: 208,
                height: 208,
                type: "svg",
                data: data.deepLink,
                image: "${url.resourcesPath}/img/telegram.svg",
                dotsOptions: { color: "#2b3072", type: "rounded" },
                cornersSquareOptions: { type: "extra-rounded" },
                imageOptions: { saveAsBlob: true, imageSize: 0.4, margin: 0 },
                backgroundOptions: { color: "#ffffff" },
                qrOptions: { errorCorrectionLevel: "M" }
              });
              qrCode.append(container);

              phoneNumberRequestPending = false;
              const prompt = document.getElementById("phone-number-prompt");
              if (prompt) prompt.hidden = true;

              startCountdown();
            })
            .catch(function () {
              console.error("Failed to fetch QR code.");
            })
            .finally(function () {
              isRefreshing = false;
            });
        }

        document.getElementById("qr-link").addEventListener("click", function (event) {
          event.preventDefault();
          const url = this.dataset.url;
          if (url) {
            winQrLink = window.open(url, "_blank");
          }
        });

        document.getElementById("qr-refresh").addEventListener("click", function () {
          fetchQRCodeDataAndRender();
        });

        function startCountdown() {
          clearInterval(interval);
          clearInterval(checkLinkInterval);
          timeLeft = duration;
          const qrContainer = document.getElementById("qr-container");
          const timer = document.getElementById("qr-timer");
          if (qrContainer) qrContainer.classList.remove("blurred");
          if (timer) timer.textContent = formatCountdown(timeLeft);

          checkLinkInterval = setInterval(function () {
            checkAuthStatus();
          }, 3000);

          interval = setInterval(function () {
            timeLeft--;
            if (timer) timer.textContent = formatCountdown(timeLeft);

            if (timeLeft <= 0) {
              clearInterval(interval);
              clearInterval(checkLinkInterval);
              if (qrContainer) qrContainer.classList.add("blurred");
              setTimeout(function () {
                fetchQRCodeDataAndRender();
              }, 2000);
            }
          }, 1000);
        }

        fetch(apiBase + "/telegram-auth/" + providerAlias + "/init", { method: 'POST' })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (d.ok) {
              console.log("Bot initialized in " + d.mode + " mode");
            } else {
              console.error("Bot init failed:", d.error);
            }
          })
          .catch(function (e) {
            console.error("Bot init error:", e);
          });

        fetchQRCodeDataAndRender();
      })();
    </script>
  <#elseif section = "socialProviders">
  </#if>
</@layout.registrationLayout>
