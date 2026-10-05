<#import "template.ftl" as layout>
<#import "password-commons.ftl" as passwordCommons>
<#--
  EDC-styled "choose a new password" page, reached from the link in the reset password email.

  Same treatment as login.ftl and login-reset-password.ftl: a subtitle under the heading and a
  <button id="kc-login"> submit, because the stock template submits with
  <input class="pf-v5-c-button ...">, which misses the EDC button styling and gives the busy
  spinner nothing to attach to.
-->
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('password','password-confirm'); section>
    <#if section = "header">
        ${msg("updatePasswordTitle")}
    <#elseif section = "form">
        <p class="subtitle">${msg("edcUpdatePasswordSubtitle")}</p>
        <div id="kc-form">
          <div id="kc-form-wrapper">
            <form id="kc-passwd-update-form" class="${properties.kcFormClass!}"
                  action="${url.loginAction}" method="post">
                <div class="${properties.kcFormGroupClass!}">
                    <label for="password-new" class="${properties.kcLabelClass!}">${msg("passwordNew")}</label>
                    <div class="${properties.kcInputGroup!}" dir="ltr">
                        <input type="password" id="password-new" name="password-new" class="${properties.kcInputClass!}"
                               autofocus autocomplete="new-password"
                               aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                        />
                        <button class="${properties.kcFormPasswordVisibilityButtonClass!}" type="button" aria-label="${msg('showPassword')}"
                                aria-controls="password-new" data-password-toggle
                                data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}" data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                            <i class="${properties.kcFormPasswordVisibilityIconShow!}" aria-hidden="true"></i>
                        </button>
                    </div>

                    <#if messagesPerField.existsError('password')>
                        <span id="input-error-password" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('password'))?no_esc}
                        </span>
                    </#if>
                </div>

                <div class="${properties.kcFormGroupClass!}">
                    <label for="password-confirm" class="${properties.kcLabelClass!}">${msg("passwordConfirm")}</label>
                    <div class="${properties.kcInputGroup!}" dir="ltr">
                        <input type="password" id="password-confirm" name="password-confirm"
                               class="${properties.kcInputClass!}"
                               autocomplete="new-password"
                               aria-invalid="<#if messagesPerField.existsError('password-confirm')>true</#if>"
                        />
                        <button class="${properties.kcFormPasswordVisibilityButtonClass!}" type="button" aria-label="${msg('showPassword')}"
                                aria-controls="password-confirm" data-password-toggle
                                data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}" data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                            <i class="${properties.kcFormPasswordVisibilityIconShow!}" aria-hidden="true"></i>
                        </button>
                    </div>

                    <#if messagesPerField.existsError('password-confirm')>
                        <span id="input-error-password-confirm" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}
                        </span>
                    </#if>
                </div>

                <@passwordCommons.logoutOtherSessions/>

                <div id="kc-form-buttons">
                    <#if isAppInitiatedAction??>
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                type="submit" id="kc-login">${msg("doSubmit")}</button>
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                type="submit" name="cancel-aia" value="true">${msg("doCancel")}</button>
                    <#else>
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                type="submit" id="kc-login">${msg("doSubmit")}</button>
                    </#if>
                </div>
            </form>
          </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
        <script src="${url.resourcesPath}/js/edc-login.js"></script>
    </#if>
</@layout.registrationLayout>