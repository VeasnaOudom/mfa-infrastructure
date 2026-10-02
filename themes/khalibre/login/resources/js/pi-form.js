function bytesToBase64(bytes) {
    const binString = Array.from(bytes, (byte) =>
        String.fromCodePoint(byte),).join("");
    return btoa(binString);
}

function base64URLToBytes(base64URLString) {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function webAuthnAuthentication(signRequest, mode) {
    if (mode === "push") {
        changeMode("webauthn");
        return;
    }
    if (!signRequest) {
        console.log("WebAuthn Authentication: Challenge data is empty!")
        return "";
    }
    let signRequestObject = JSON.parse(signRequest.replace(/(&quot;)/g, "\""));
    try {
        const webAuthnSignResponse = window.pi_webauthn.sign(signRequestObject);
        webAuthnSignResponse.then((webauthnResponse) => {
            formResult.webAuthnSignResponse = JSON.stringify(webauthnResponse);
            submitForm();
        });
    } catch (err) {
        console.log(err);
    }
}

function passkeyAuthentication(passkeyChallenge, mode) {
    if (mode === "push") {
        changeMode("passkey");
        return;
    }
    if (!passkeyChallenge) {
        console.log("Passkey Authentication: Challenge data is empty!")
        return "";
    }
    formResult.passkeyLoginCancelled = false;
    let challengeObject = JSON.parse(passkeyChallenge.replace(/(&quot;)/g, "\""));
    let userVerification = "preferred";
    if (["required", "preferred", "discouraged"].includes(challengeObject.user_verification)) {
        userVerification = challengeObject.user_verification;
    }
    navigator.credentials.get({
        publicKey: {
            challenge: Uint8Array.from(challengeObject.challenge, c => c.charCodeAt(0)),
            rpId: challengeObject.rpId,
            userVerification: userVerification,
        },
    }).then(credential => {
        let params = {
            transaction_id: challengeObject.transaction_id,
            credential_id: credential.id,
            authenticatorData: bytesToBase64(
                new Uint8Array(credential.response.authenticatorData)),
            clientDataJSON: bytesToBase64(new Uint8Array(credential.response.clientDataJSON)),
            signature: bytesToBase64(new Uint8Array(credential.response.signature)),
            userHandle: bytesToBase64(new Uint8Array(credential.response.userHandle)),
        };
        formResult.passkeySignResponse = JSON.stringify(params);
        submitForm();
    }, function (error) {
        console.log("Passkey authentication error: " + error);
        formResult.passkeyLoginCancelled = true;
    });
}

// Use the passkey_registration from the response as input to this function
function registerPasskey(registrationData) {
    let data = JSON.parse(registrationData.replace(/(&quot;)/g, "\""));
    let excludedCredentials = [];
    if (data.excludeCredentials) {
        for (const cred of data.excludeCredentials) {
            excludedCredentials.push({
                id: base64URLToBytes(cred.id),
                type: cred.type,
            });
        }
    }

    return navigator.credentials.create({
        publicKey: {
            rp: data.rp,
            user: {
                id: base64URLToBytes(data.user.id),
                name: data.user.name,
                displayName: data.user.displayName
            },
            challenge: Uint8Array.from(data.challenge, c => c.charCodeAt(0)),
            pubKeyCredParams: data.pubKeyCredParams,
            excludeCredentials: excludedCredentials,
            authenticatorSelection: data.authenticatorSelection,
            timeout: data.timeout,
            extensions: {
                credProps: true,
            },
            attestation: data.attestation
        }
    }).then(function (publicKeyCred) {
        let params = {
            credential_id: publicKeyCred.id,
            rawId: bytesToBase64(new Uint8Array(publicKeyCred.rawId)),
            authenticatorAttachment: publicKeyCred.authenticatorAttachment,
            attestationObject: bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject)),
            clientDataJSON: bytesToBase64(new Uint8Array(publicKeyCred.response.clientDataJSON)),
        }
        if (publicKeyCred.response.attestationObject) {
            params.attestationObject = bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject));
        }
        const extResults = publicKeyCred.getClientExtensionResults();
        if (extResults.credProps) {
            params.credProps = extResults.credProps;
        }
        formResult.passkeyRegistrationResponse = JSON.stringify(params);
        submitForm();
    }, function (error) {
        console.log("Error while registering passkey:");
        console.log(error);
        return null;
    });
}

function requestPasskeyLogin() {
    formResult.passkeyLoginRequested = true;
    submitForm();
}

function authenticationReset() {
    formResult.authenticationResetRequested = true;
    submitForm();
}

function cancelEnrollmentViaMc() {
    formResult.enrollmentViaMultichallengeCancelled = true;
    submitForm();
}

function setPushReload(intervalSeconds) {
    if (!intervalSeconds) {
        console.log("Interval seconds is empty, using default of 2s.");
        intervalSeconds = 2;
    }
    window.setTimeout(() => {
        submitForm();
    }, parseInt(intervalSeconds) * 1000);
}

function setAutoSubmit(inputLength) {
    let otpField = document.querySelector("#otp")
    if (otpField) {
        otpField.addEventListener("keyup", function () {
            // catch parse int error?
            if (otpField.value.length === parseInt(inputLength)) {
                submitForm();
            }
        });
    }
}

function changeMode(newMode) {
    //console.log("changeMode to " + newMode);
    formResult.modeChanged = true;
    formResult.newMode = newMode;
    submitForm();
}

function submitForm() {
    if (!formResult.modeChanged && !khSignInReady()) {
        return;
    }
    if (!formResult.modeChanged) {
        khLockSignInButton();
    }
    if (!window.location.origin) {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':'
            + window.location.port : '');
    }
    formResult.origin = window.location.origin;
    //console.log("Submit, formResult:");
    //console.log(formResult);
    document.querySelector("#authenticationFormResult").value = JSON.stringify(formResult);
    document.forms["kc-otp-login-form"].requestSubmit();
}

function startPollingInBrowser(url, transactionId, resourcesPath) {
    let pushButton = document.querySelector("#pushButton");
    if (pushButton) {
        pushButton.style.display = "none";
    }
    let worker;
    if (typeof (Worker) !== "undefined") {
        if (typeof (worker) == "undefined") {
            worker = new Worker(resourcesPath + "/js/pi-pollTransaction.worker.js");
            let form = document.querySelector("#kc-login")
            if (form) {
                form.addEventListener('click', function (e) {
                    if (worker) {
                        worker.terminate();
                        worker = undefined;
                    }
                });
            }
            worker.postMessage({'cmd': 'url', 'msg': url});
            worker.postMessage({'cmd': 'transactionID', 'msg': transactionId});
            worker.postMessage({'cmd': 'start'});
            worker.addEventListener('message', function (e) {
                let data = e.data;
                switch (data.status) {
                    case 'success':
                        submitForm();
                        break;
                    case 'cancel':
                        formResult.pollInBrowserCancelled = true;
                        worker = undefined;
                        submitForm();
                        break;
                    case 'error':
                        console.log("Poll in Browser error: " + data.message);
                        formResult.pollInBrowserCancelled = true;
                        worker = undefined;
                        if (pushButton) {
                            pushButton.style.display = "initial";
                        }
                }
            });
        }
    } else {
        console.log("Poll in Browser error: The browser doesn't support WebWorker.");
        worker.terminate();
        formResult.pollInBrowserCancelled = true;
        formResult.pollInBrowserError = "The browser doesn't support WebWorker.";
        if (pushButton) {
            pushButton.style.display = "initial";
        }
    }
}

function setLoginOptionsVisibility() {
    let ids = ["passkeyInitiateButton", "otpButton", "pushButton", "webAuthnButton"]
    let shouldShow = false;
    for (let id of ids) {
        let element = document.querySelector("#" + id);
        if (element && window.getComputedStyle(element).display !== "none" && window.getComputedStyle(element).display !== "hidden") {
            shouldShow = true;
            break;
        }
    }
    if (!shouldShow) {
        let element = document.querySelector("#alternateToken");
        if (element) {
            element.style.display = "none";
        }
    }

    // If the otp input field is visible, hide the otp button
    let otpInput = document.querySelector("#otp");
    if (otpInput && otpInput.style.display !== "none" && otpInput.style.display !== "hidden") {
        let element = document.querySelector("#otpButton");
        if (element) {
            element.style.display = "none";
        }
    }
}

function khVisibleInputs() {
    return ["#otp", "#username", "#password"]
        .map(function (selector) { return document.querySelector(selector); })
        .filter(function (element) {
            return element && window.getComputedStyle(element).display !== "none"
                && window.getComputedStyle(element).display !== "hidden";
        });
}

/**
 * Realm resource base for the privacyIDEA endpoints, e.g. "/realms/mfa".
 *
 * Keycloak's UrlBean exposes no realmUrl accessor, so the base is derived from the form action
 * this page already carries.
 */
function edcRealmBase() {
    var form = document.getElementById("kc-otp-login-form");
    var action = form ? form.getAttribute("action") : "";
    var marker = action.indexOf("/login-actions");
    return marker > 0 ? action.substring(0, marker) : "";
}

var EDC_ICONS = {
    telegram: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M21.9 4.3 18.7 19.4c-.2 1-.8 1.2-1.6.8l-4.5-3.3-2.2 2.1c-.2.2-.4.4-.9.4l.3-4.5 8.2-7.4c.4-.3-.1-.5-.6-.2L6.2 13.5l-4.4-1.4c-1-.3-1-1 .2-1.5l17.2-6.6c.8-.3 1.5.2 1.2 1.5z"/></svg>',
    totp: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg>',
    email: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 6 10-6"/></svg>'
};

function edcChannelRow(icon, name, detail, state, stateClass) {
    var row = document.createElement("div");
    row.className = "edc-channel";
    var ico = document.createElement("span");
    ico.className = "edc-channel-ico";
    ico.setAttribute("aria-hidden", "true");
    ico.innerHTML = icon;
    var body = document.createElement("span");
    body.className = "edc-channel-body";
    var nameEl = document.createElement("span");
    nameEl.className = "edc-channel-name";
    nameEl.textContent = name;
    body.appendChild(nameEl);
    if (detail) {
        var detailEl = document.createElement("span");
        detailEl.className = "edc-channel-detail";
        detailEl.textContent = detail;
        body.appendChild(detailEl);
    }
    var stateEl = document.createElement("span");
    stateEl.className = "edc-channel-state " + stateClass;
    stateEl.textContent = state;
    row.appendChild(ico);
    row.appendChild(body);
    row.appendChild(stateEl);
    return row;
}

/**
 * Renders the "where we sent it" rows.
 *
 * The channel state lives in authentication-session notes, which FreeMarker cannot reach, so it is
 * fetched from the session-authorised /privacyidea/channels endpoint. If that fails we simply show
 * no rows rather than claiming channels that may not work.
 */
function edcFetchChannels() {
    var host = document.getElementById("edcChannels");
    var base = edcRealmBase();
    if (!host || !base) {
        return Promise.resolve(null);
    }
    return window.fetch(base + "/privacyidea/channels",
        {credentials: "same-origin", headers: {"Accept": "application/json"}})
        .then(function (response) {
            return response.ok ? response.json() : null;
        })
        .catch(function () {
            return null;
        })
        .then(function (data) {
            edcRenderChannels(data);
            return data;
        });
}

function edcRenderChannels(data) {
    var host = document.getElementById("edcChannels");
    if (!host || !data) {
        return;
    }
    var rows = [];
    if (data.telegram) {
        var handle = data.telegramHandle || "";
        if (handle && handle.charAt(0) !== "@") {
            handle = "@" + handle;
        }
        rows.push(edcChannelRow(EDC_ICONS.telegram, host.dataset.telegram, handle,
            host.dataset.sent, "edc-state-sent"));
    }
    if (data.totp) {
        rows.push(edcChannelRow(EDC_ICONS.totp, host.dataset.authenticator,
            host.dataset.authenticatorDetail, host.dataset.available, "edc-state-available"));
    }
    if (data.email) {
        rows.push(edcChannelRow(EDC_ICONS.email, host.dataset.email,
            data.emailMasked || "", host.dataset.sent, "edc-state-sent"));
    }
    host.innerHTML = "";
    rows.forEach(function (row) { host.appendChild(row); });
    // No usable channel means no chooser: better than offering one that cannot deliver.
    host.hidden = rows.length === 0;
    edcApplyExpiry(data.expiresAt);
}

function edcInitChannels() {
    edcFetchChannels();
}

function edcOtpBoxes() {
    return document.querySelectorAll("#edcOtpBoxes .edc-otp-box");
}

function edcOtpExpectedLength() {
    let boxes = document.getElementById("edcOtpBoxes");
    return boxes ? parseInt(boxes.dataset.length || "6", 10) : 0;
}

function edcSyncHiddenOtp() {
    let target = document.querySelector("#otp");
    if (!target) {
        return;
    }
    let code = Array.prototype.map.call(edcOtpBoxes(), function (box) {
        return box.value.trim();
    }).join("");
    target.value = code;
}

var edcAutoSubmitFired = false;

/** True once every digit box holds exactly one digit. */
function edcOtpComplete() {
    var hidden = document.querySelector("#otp");
    if (!hidden || !document.getElementById("edcOtpBoxes")) {
        return false;
    }
    return hidden.value.replace(/\s/g, "").length === edcOtpExpectedLength();
}

/**
 * Signs in as soon as the code is complete, so the user does not have to press the button.
 *
 * submitForm() already refuses to submit an incomplete code and locks the button, so this only
 * fires once per code; the flag keeps a second keyup or a stray paste from double submitting.
 */
function edcMaybeAutoSubmit() {
    if (edcAutoSubmitFired || !edcOtpComplete()) {
        return;
    }
    var button = khSignInButton();
    if (button && button.dataset.edcBusy === "true") {
        return;
    }
    edcAutoSubmitFired = true;
    submitForm();
}

function edcInitOtpBoxes() {
    let boxes = edcOtpBoxes();
    let hidden = document.querySelector("#otp");
    if (boxes.length === 0 || !hidden) {
        return;
    }
    hidden.focus = function () {
        let empty = Array.prototype.find.call(boxes, function (box) { return !box.value; });
        (empty || boxes[0]).focus();
    };
    hidden.setAttribute("autofocus", "autofocus");
    Array.prototype.forEach.call(boxes, function (box, index) {
        box.addEventListener("input", function () {
            box.value = box.value.replace(/[^0-9]/g, "").slice(-1);
            if (box.value && index < boxes.length - 1) {
                boxes[index + 1].focus();
            }
            edcSyncHiddenOtp();
            khSyncSignInButton();
            edcMaybeAutoSubmit();
        });
        box.addEventListener("keydown", function (event) {
            if (event.key === "Backspace" && !box.value && index > 0) {
                event.preventDefault();
                boxes[index - 1].value = "";
                boxes[index - 1].focus();
                edcSyncHiddenOtp();
                khSyncSignInButton();
            } else if (event.key === "ArrowLeft" && index > 0) {
                boxes[index - 1].focus();
            } else if (event.key === "ArrowRight" && index < boxes.length - 1) {
                boxes[index + 1].focus();
            }
        });
        box.addEventListener("paste", function (event) {
            event.preventDefault();
            let pasted = (event.clipboardData || window.clipboardData).getData("text") || "";
            pasted = pasted.replace(/[^0-9]/g, "");
            Array.prototype.forEach.call(boxes, function (target, offset) {
                target.value = pasted.charAt(offset) || "";
            });
            let last = Math.min(pasted.length, boxes.length - 1);
            boxes[last].focus();
            edcSyncHiddenOtp();
            khSyncSignInButton();
            edcMaybeAutoSubmit();
        });
        box.addEventListener("focus", function () { box.select(); });
    });
    Array.prototype.forEach.call(boxes, function (box) { box.value = ""; });
    edcSyncHiddenOtp();
    edcAutoSubmitFired = false;
    boxes[0].focus();
}

var edcCountdownTimer = null;

/** Replaces any running countdown so timers cannot stack up. */
function edcStartCountdown(deadlineMs) {
    var label = document.getElementById("edcOtpExpiryText");
    if (!label) {
        return;
    }
    if (edcCountdownTimer !== null) {
        window.clearInterval(edcCountdownTimer);
        edcCountdownTimer = null;
    }
    label.style.fontWeight = 'bold';
    var tick = function () {
        var left = Math.max(0, Math.round((deadlineMs - Date.now()) / 1000));
        var minutes = Math.floor(left / 60);
        var seconds = left % 60;
        label.textContent = minutes + ":" + (seconds < 10 ? "0" : "") + seconds;
    };
    tick();
    edcCountdownTimer = window.setInterval(tick, 1000);
}

function edcInitCountdown() {
    var node = document.getElementById("edcOtpExpiry");
    if (node) {
        // Placeholder until /channels reports the real expiry.
        edcStartCountdown(Date.now() + 300000);
    }
}

/** Starts the countdown from the expiry the server computed for the code it just issued. */
function edcApplyExpiry(expiresAtSeconds) {
    if (expiresAtSeconds) {
        edcStartCountdown(expiresAtSeconds * 1000);
    }
}

function edcInitResend() {
    let button = document.getElementById("edcOtpResend");
    if (!button) {
        return;
    }
    let label = button.textContent;
    button.addEventListener("click", function () {
        if (button.disabled || button.dataset.busy === "1") {
            return;
        }
        button.dataset.busy = "1";
        button.disabled = true;
        button.textContent = button.dataset.sending || "Sending\u2026";
        window.fetch(edcRealmBase() + "/privacyidea/resend", {
            method: "POST",
            credentials: "same-origin",
            headers: {"Content-Type": "application/json"},
            body: "{}"
        }).then(function (response) {
            button.textContent = response.ok ? (button.dataset.sent || "New code sent")
                                             : (button.dataset.failed || "Could not send a new code");
        }).catch(function () {
            button.textContent = button.dataset.failed || "Could not send a new code";
        }).then(function () {
            window.setTimeout(function () {
                button.dataset.busy = "0";
                button.disabled = false;
                button.textContent = label;
                edcStartFreshCountdown();
            }, 4000);
        });
    });
}

function edcStartFreshCountdown() {
    var boxes = document.getElementById("edcOtpBoxes");
    var hidden = document.querySelector("#otp");
    if (boxes && hidden) {
        Array.prototype.forEach.call(edcOtpBoxes(), function (box) { box.value = ""; });
        edcSyncHiddenOtp();
        edcAutoSubmitFired = false;
        // The previous code is gone, so re-enable submitting for the new one.
        khUnlockSignInButton();
        edcOtpBoxes()[0].focus();
    }
    // Re-read the channels endpoint: the resend issued a new code with a new expiry.
    edcFetchChannels();
}

function edcInitOtp() {
    edcInitChannels();
    edcInitOtpBoxes();
    edcInitCountdown();
    edcInitResend();
}

function khSignInReady() {
    let boxes = document.getElementById("edcOtpBoxes");
    let otp = document.querySelector("#otp");
    if (boxes && otp) {
        return otp.value.replace(/\s/g, "").length === edcOtpExpectedLength();
    }
    let inputs = khVisibleInputs();
    if (inputs.length === 0) {
        return true;
    }
    return inputs.every(function (element) { return element.value.trim().length > 0; });
}

function khSignInButton() {
    return document.querySelector("#kc-otp-login-form #kc-login");
}

function khLockSignInButton() {
    let button = khSignInButton();
    if (!button || button.dataset.edcBusy === "true") {
        return;
    }
    button.dataset.edcBusy = "true";
    button.disabled = true;
    button.classList.remove("kh-btn-inactive");
    button.classList.add("is-loading");
}

function khUnlockSignInButton() {
    let button = khSignInButton();
    if (!button) {
        return;
    }
    delete button.dataset.edcBusy;
    button.classList.remove("is-loading");
    khSyncSignInButton();
}

function khSyncSignInButton() {
    let button = khSignInButton();
    if (!button || button.dataset.edcBusy === "true") {
        return;
    }
    let ready = khSignInReady();
    button.disabled = !ready;
    button.classList.toggle("kh-btn-inactive", !ready);
}

function khInitSignInButton() {
    let form = document.querySelector("#kc-otp-login-form");
    if (!form) {
        return;
    }
    form.addEventListener("input", khSyncSignInButton);
    form.addEventListener("change", khSyncSignInButton);
    window.addEventListener("pageshow", khUnlockSignInButton);
    khSyncSignInButton();
}

function khInitOtpPage() {
    khInitSignInButton();
    edcInitOtp();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", khInitOtpPage);
} else {
    khInitOtpPage();
}
