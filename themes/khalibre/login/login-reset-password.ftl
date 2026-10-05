<#import "template.ftl" as layout>
<#--
  EDC-styled forgot password.

  Keycloak serves both steps of this flow from this one template: the username form, and the
  confirmation, which re-renders the form carrying a success message.

  The stock template submits with <input class="pf-v5-c-button ...">, which misses the EDC button
  styling and has no id for the busy spinner to attach to, so this version uses the same
  <button id="kc-login"> markup as the sign-in and OTP pages.
-->
<#--
  displayInfo is deliberately off. ResetCredentialEmail finishes with
  forkWithSuccessMessage(EMAIL_SENT), which re-renders this same page carrying a success message,
  so the "check your inbox" text arrives through displayMessage. Rendering an info section as well
  puts a second, unstyled box underneath the form that duplicates the subtitle.
-->
<@layout.registrationLayout displayInfo=false displayMessage=!messagesPerField.existsError('username'); section>
    <#if section = "header">
        ${msg("emailForgotTitle")}
    <#elseif section = "form">
        <p class="subtitle">${msg("edcResetPasswordSubtitle")}</p>
        <div id="kc-form">
          <div id="kc-form-wrapper">
            <form id="kc-reset-password-form" class="${properties.kcFormClass!}"
                  action="${url.loginAction}" method="post">
                <div class="${properties.kcFormGroupClass!}">
                    <label for="username" class="${properties.kcLabelClass!}"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>
                    <input type="text" id="username" name="username" class="${properties.kcInputClass!}"
                           autofocus value="${(auth.attemptedUsername!'')}"
                           aria-invalid="<#if messagesPerField.existsError('username')>true</#if>" dir="ltr"/>
                    <#if messagesPerField.existsError('username')>
                        <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                    ${kcSanitize(messagesPerField.get('username'))?no_esc}
                        </span>
                    </#if>
                </div>

                <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                    <div id="kc-form-options">
                        <div>
                            <span><a href="${url.loginUrl}">${kcSanitize(msg("backToLogin"))?no_esc}</a></span>
                        </div>
                    </div>

                    <div id="kc-form-buttons">
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                type="submit" id="kc-login">${msg("doSubmit")}</button>
                    </div>
                </div>
            </form>
          </div>
        </div>
        <script src="${url.resourcesPath}/js/edc-login.js"></script>
    </#if>
</@layout.registrationLayout>
