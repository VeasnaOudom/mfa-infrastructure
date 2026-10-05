<#import "template.ftl" as layout>
<!-- BASE JS SCRIPT: Create the formResult object (AuthenticationFormResult.java) -->
<script>
    //let data = "${authenticationForm}";
    //console.log(data.replace(/(&quot;)/g, "\""));
    let formResult = {
        passkeyLoginRequested: false
    };
</script>
<head>
    <link rel="stylesheet" href="${url.resourcesPath}/css/pi-form.css">
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-webauthn.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-form.js"></script>
</head>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle", (realm.displayName!'')?has_content?then(realm.displayName, realm.name))}
    <#elseif section = "header">
        ${msg("loginTitleHtml", (realm.displayName!'')?has_content?then(realm.displayName, realm.name))}
    <#elseif section = "form">
        <#-- Auth notes are not exposed to FreeMarker (Keycloak binds "authenticationSession" to an
             id/tabId bean), so the channel list is filled in by JS from the /privacyidea/channels
             endpoint, which is authorised for this OTP challenge only. -->
        <#assign isOtpMode = authenticationForm.mode = "otp">
        <#assign useBoxes = isOtpMode && !(authenticationForm.passkeyRegistration?has_content)>
        <form id="kc-otp-login-form" onsubmit="submitForm();"
              class="${properties.kcFormClass!}"
              action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div>
                    <!-- IMAGES AND PROMPTS -->
                    <!-- Show images if there is no error message, or if push has not been accepted yet -->
                    <#if !authenticationForm.errorMessage?has_content || authenticationForm.errorMessage == "push_auth_not_verified">
                        <#if authenticationForm.mode = "push" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.pushImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.pushImage}">
                                </div>
                            <#elseif authenticationForm.smartphoneImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.smartphoneImage}">
                                </div>
                            </#if>
                            <#if authenticationForm.pushMessage?has_content>
                                <h4 class="bold-text">${authenticationForm.pushMessage}</h4>
                            </#if>
                        <#elseif authenticationForm.mode = "webauthn" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.webAuthnImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.webAuthnImage}">
                                </div>
                            </#if>
                        <#elseif authenticationForm.mode = "otp" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.otpImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.otpImage}">
                                </div>
                            </#if>
                        <#elseif authenticationForm.mode = "usernamepassword" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.usernamepasswordPrompt')}</h4>
                        <#elseif authenticationForm.mode = "username" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.usernamePrompt')}</h4>
                        <#elseif authenticationForm.mode = "password" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.passwordPrompt')}</h4>
                        </#if>
                        <!-- ENROLLMENT LINK & CANCEL ENROLLMENT -->
                        <#if authenticationForm.enrollmentLink?has_content>
                            <a href="${authenticationForm.enrollmentLink}"
                               target="_blank">${msg('privacyidea.enrollmentLinkText')}</a>
                        </#if>
                        <#if authenticationForm.enrollViaMultichallengeOptional>
                            <br>
                            <input class="pf-v5-c-button pf-m-block" id="cancelEnrollment"
                                   value="${msg('privacyidea.cancelEnrollment')}" name="cancelEnrollment"
                                   type="button" onclick="cancelEnrollmentViaMc()"/>
                        </#if>
                    <#else>
                        <!-- ERROR MESSAGE -->
                        <div class="${properties.kcContentWrapperClass!}">
                            <div>
                                <label for="login-error">
                                    <span class="${properties.kcLabelClass!}">
                                        <#if authenticationForm.errorMessage == "push_auth_not_verified">
                                            <p style="color:red;">${msg('privacyidea.pushNotYetVerified')}</p>
                                        <#elseif authenticationForm.errorMessage == "passkey_authentication_failed">
                                            <p style="color:red;">${msg('privacyidea.passkeyAuthenticationFailed')}</p>
                                        <#else>
                                            ${authenticationForm.errorMessage}
                                        </#if>
                                    </span>
                                </label>
                            </div>
                        </div>
                    </#if>
                    <!-- USERNAME INPUT -->
                    <#if ["usernamepassword", "username"]?seq_contains(authenticationForm.mode)
                    && !(authenticationForm.passkeyRegistration?has_content)>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="username"><span class="${properties.kcLabelClass!}">Username</span></label>
                            </div>
                            <div class="${properties.kcInputWrapperClass!}">
                                <input id="username" name="username" type="text" class="${properties.kcInputClass!}"
                                       value="" autofocus/>
                            </div>
                        </div>
                    </#if>
                    <!-- PASSWORD INPUT -->
                    <#if ["usernamepassword", "password"]?seq_contains(authenticationForm.mode)
                    && !(authenticationForm.passkeyRegistration?has_content)>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="password"><span class="${properties.kcLabelClass!}">Password</span></label>
                            </div>
                            <div class="${properties.kcInputWrapperClass!}">
                                <input id="password" name="password" type="password" class="${properties.kcInputClass!}"
                                       value="" autofocus/>
                            </div>
                        </div>
                    </#if>
                    <!-- OTP INPUT -->
                    <#if !(["usernamepassword", "username", "push", "passkey", "passkeyonly"]?seq_contains(authenticationForm.mode))
                    &&  !(authenticationForm.passkeyRegistration?has_content)>
                        <#if useBoxes>
                            <div class="edc-otp">
                                <h1 class="edc-otp-title">${msg('edc.otp.enterYourCode')}</h1>
                                <p class="edc-otp-subtitle">${msg('edc.otp.enterYourCodeDescription')}</p>
                                <#-- "Where we sent it" chooser. Rows are built by pi-form.js from the
                                     /privacyidea/channels response so only real channels appear. -->
                                <div class="edc-channels" id="edcChannels" role="group" hidden
                                     aria-label="${msg('edc.otp.whereSent')}"
                                     data-telegram="${msg('edc.otp.telegram')}"
                                     data-authenticator="${msg('edc.otp.authenticator')}"
                                     data-authenticator-detail="${msg('edc.otp.authenticatorDetail')}"
                                     data-email="${msg('edc.otp.email')}"
                                     data-backup-code="${msg('edc.otp.backupCode')}"
                                     data-sent="${msg('edc.otp.sent')}"
                                     data-available="${msg('edc.otp.available')}"></div>
                        </#if>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div>
                                <label for="otp"><span class="${properties.kcLabelClass!}">
                                        <#if (authenticationForm.otpMessage)?has_content>
                                            ${authenticationForm.otpMessage}
                                        <#else>
                                            ${msg('privacyidea.otpPrompt')}
                                        </#if>
                                    </span></label>
                            </div>
                            <#if useBoxes>
                                <#-- Six boxes are decorative: JS mirrors them into the single #otp field
                                     that the privacyIDEA authenticator actually reads. -->
                                <div class="edc-otp-boxes" id="edcOtpBoxes" data-length="6">
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 1)}"/>
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 2)}"/>
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 3)}"/>
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 4)}"/>
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 5)}"/>
                                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                                           maxlength="1" autocomplete="off" aria-label="${msg('edc.otp.digit', 6)}"/>
                                </div>
                                <#-- Only shown when the user actually enrolled a TAN token. Same OTP
                                     field, so nothing extra to submit - privacyIDEA validates a backup
                                     code through the ordinary check call. -->
                                <p class="edc-otp-hint" id="edcBackupCodeHint" hidden>
                                    <#-- Bold phrase supplied by pi-form.js so the emphasis stays with
                                         the copy that can change, not baked into the markup here. -->
                                    <span data-prefix="${msg('edc.otp.backupCodeHintPrefix')}">${msg('edc.otp.backupCodeHintPrefix')}</span>
                                    <b>${msg('edc.otp.backupCode')}</b>
                                    <span data-suffix="${msg('edc.otp.backupCodeHintSuffix')}">${msg('edc.otp.backupCodeHintSuffix')}</span>
                                </p>
                                <div class="edc-otp-foot">
                                    <span class="edc-otp-expiry" id="edcOtpExpiry">
                                        <span id="edcOtpExpiryLabel">${msg('edc.otp.expiresInLabel')}</span>
                                        <span id="edcOtpExpiryText">--:--</span>
                                    </span>
                                    <button type="button" class="edc-otp-resend" id="edcOtpResend"
                                            data-sending="${msg('edc.otp.resending')}"
                                            data-sent="${msg('edc.otp.resendSent')}"
                                            data-failed="${msg('edc.otp.resendFailed')}">
                                        ${msg('edc.otp.resend')}
                                    </button>
                                </div>
                                <div class="edc-otp-note edc-otp-expired" id="edcOtpExpired" hidden>
                                    <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M12 2 1 21h22L12 2zm1 14h-2v2h2v-2zm0-6h-2v5h2v-5z"/></svg>
                                    <span>${msg('edc.otp.expired')}</span>
                                    <button type="button" class="edc-otp-expired-action"
                                            onclick="document.querySelector('#edcOtpResend').click()">
                                        ${msg('edc.otp.getNewCode')}
                                    </button>
                                </div>
                                <div class="edc-otp-note">
                                    <span>${msg('edc.otp.neverShare')}</span>
                                </div>
                            </#if>
                            <div>
                                <input id="otp" name="otp" type="password"
                                       <#if useBoxes>class="edc-otp-hidden" aria-hidden="true" tabindex="-1"
                                       <#else>class="${properties.kcInputClass!}" autofocus</#if>
                                       value="" autocomplete="new-password"/>
                            </div>
                        </div>
                    </#if>
                    <!-- Passkey Registration (enroll_via_multichallenge) with retry button -->
                    <#if authenticationForm.passkeyRegistration?has_content>
                        <script>
                            registerPasskey("${authenticationForm.passkeyRegistration}");
                        </script>
                        <input class="pf-v5-c-button pf-m-primary pf-m-block" id="retryPasskeyRegistration"
                               value="${msg('privacyidea.passkeyRegisterRetryButton')}" name="retryPasskeyRegistration"
                               type="button" onclick="registerPasskey('${authenticationForm.passkeyRegistration}')"/>
                    </#if>
                </div>
            </div>

            <!-- Sign In Button -->
            <#if !(["passkey", "push", "passkeyonly"]?seq_contains(authenticationForm.mode))
            && !(authenticationForm.passkeyRegistration?has_content)>
                <div id="kc-username">
                    <button class="pf-v5-c-button pf-m-primary pf-m-block" name="login" id="kc-login"
                            type="submit" value="${msg('privacyidea.signIn')}">${msg('privacyidea.signIn')}</button>
                </div>
            </#if>

            <!-- AuthenticationFormResult: JSON of that class with the data that has to be passed back -->
            <input id="authenticationFormResult" name="authenticationFormResult" value="" type="hidden">
            <!-- Readonly authenticationForm is also passed back to preserve the state -->
            <input id="authenticationForm" name="authenticationForm" value="${authenticationForm!""}" type="hidden">

            <!-- Passkey login feature toggle -->
            <#if !authenticationForm.disablePasskeyLogin>
                <!-- Passkey Button: Initiate passkey login by getting a challenge -->
            <#if !authenticationForm.passkeyRegistration?has_content && authenticationForm.firstStep>
                <div class="${properties.kcFormGroupClass!}">
                    <input class="pf-v5-c-button pf-m-block" type="button"
                           name="passkeyInitiateButton" id="passkeyInitiateButton" onclick="requestPasskeyLogin()"
                           value="${msg('privacyidea.passkeyInitiateButton')}"/>
                </div>
            </#if>

                <!-- Passkey Authentication with retry button -->
            <#if authenticationForm.passkeyChallenge?has_content && (!authenticationForm.errorMessage?has_content
            || authenticationForm.errorMessage == "passkey_authentication_failed")>

            <input class="pf-v5-c-button pf-m-primary pf-m-block" id="retryPasskeyAuthentication"
                   value="${msg('privacyidea.passkeyRetryButton')}" name="retryPasskeyAuthentication" type="button"
                   onclick="passkeyAuthentication('${authenticationForm.passkeyChallenge}', '${authenticationForm.mode}')"/>
            <input class="pf-v5-c-button pf-m-block" id="resetAuthentication"
                   value="${msg('privacyidea.resetLogin')}" name="resetAuthentication" type="button"
                   onclick="authenticationReset()"/>
            </#if>
                <!-- Only trigger passkey authentication automatically if there has been no error before -->
            <#if authenticationForm.passkeyChallenge?has_content && !authenticationForm.errorMessage?has_content>
                <script>
                    passkeyAuthentication("${authenticationForm.passkeyChallenge}", "${authenticationForm.mode}");
                </script>
            </#if>
            </#if> <!-- ENDIF PASSKEY DISABLED -->
            <!-- END OF PASSKEY -->

            <!-- AUTO SUBMIT -->
            <#if authenticationForm.autoSubmitLength?has_content>
                <script>
                    setAutoSubmit("${authenticationForm.autoSubmitLength}");
                </script>
            </#if>
            <!-- PUSH POLLING-->
            <#if authenticationForm.mode = "push">
                <script>
                    setPushReload(${authenticationForm.pollInterval});
                </script>
            </#if>
            <#if authenticationForm.pollInBrowserAvailable>
                <script>
                    startPollingInBrowser("${authenticationForm.pollInBrowserURL}", "${authenticationForm.transactionId}", "${url.resourcesPath}");
                </script>
            </#if>
            <!-- WEBAUTHN -->
            <#if authenticationForm.mode = "webauthn" && authenticationForm.webAuthnSignRequest?has_content>
                <script>
                    webAuthnAuthentication('${authenticationForm.webAuthnSignRequest}', '${authenticationForm.mode}');
                </script>
            </#if>

            <!-- PASSKEY ONLY MODE -->
            <#if authenticationForm.mode = "passkeyonly" && !authenticationForm.passkeyRegistration?has_content>
                <script>requestPasskeyLogin()</script>
            </#if>

            <!-- OTHER LOGIN OPTIONS DIV -->
            <!-- Custom Code Hide Login Option -->
            <#if false && !authenticationForm.firstStep && !authenticationForm.passkeyChallenge?has_content && authenticationForm.mode != "passkeyonly"
            && !authenticationForm.passkeyRegistration?has_content && !authenticationForm.enrollViaMultichallenge>
                <div id="alternateToken" class="${properties.kcFormButtonsClass!}">
                    <h3 id="alternateTokenHeader">${msg('privacyidea.alternateLoginOptions')}</h3>
                    <!-- Passkey Button: Initiate passkey login by getting a challenge -->
                    <#if !authenticationForm.disablePasskeyLogin && !authenticationForm.passkeyRegistration?has_content
                    && !authenticationForm.firstStep>
                        <div class="${properties.kcFormGroupClass!}">
                            <input class="pf-v5-c-button pf-m-block" type="button"
                                   name="passkeyInitiateButton" id="passkeyInitiateButton"
                                   onclick="requestPasskeyLogin()"
                                   value="${msg('privacyidea.passkeyInitiateButton')}"/>
                        </div>
                    </#if>
                    <!-- OTP Button -->
                    <#if authenticationForm.otpAvailable && authenticationForm.mode != "otp">
                        <input class="pf-v5-c-button pf-m-block" id="otpButton"
                               name="otpButton" onclick="changeMode('otp')"
                               type="button" value="${msg('privacyidea.otpButton')}"/>
                    </#if>
                    <!-- Push Button -->
                    <#if authenticationForm.pushAvailable && authenticationForm.mode != "push">
                        <input class="pf-v5-c-button pf-m-block" id="pushButton"
                               name="pushButton" onclick="changeMode('push')"
                               type="button" value="${msg('privacyidea.pushButton')}"/>
                    </#if>
                    <!-- WebAuthn Button -->
                    <#if authenticationForm.webAuthnSignRequest?has_content>
                        <input class="pf-v5-c-button pf-m-block" id="webAuthnButton"
                               onclick="webAuthnAuthentication('${authenticationForm.webAuthnSignRequest}', '${authenticationForm.mode}')"
                               name="webauthnButton" type="button"
                               value="${msg('privacyidea.webauthnButton')}"/>
                    </#if>
                </div>
            </#if>
            <script>
                // If none of the buttons of the "other login options" are shown, hide the whole div with the text
                // This is easier than having a huge check for the div, as each button can have its own logic
                setLoginOptionsVisibility();
            </script>
        </form>
    </#if>
</@layout.registrationLayout>