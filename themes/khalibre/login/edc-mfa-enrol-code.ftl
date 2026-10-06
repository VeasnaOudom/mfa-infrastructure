<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        <#if channel == 'email'>${msg('edc.enrol.emailTitle')}<#else>${msg('edc.enrol.totpTitle')}</#if>
    <#elseif section = "form">
        <#if error??>
            <div class="edc-alert" role="alert">
                <span>${msg(error!'')}</span>
            </div>
        </#if>

        <#if channel == 'email'>
            <p class="edc-otp-subtitle">
                ${msg('edc.enrol.emailIntro', (emailMasked!''))}
            </p>
        <#else>
            <p class="edc-otp-subtitle">${msg('edc.enrol.totpIntro')}</p>
            <div id="edc-qr" class="edc-qr" data-uri="${enrolmentUri!}"></div>
            <details class="edc-setup-key">
                <summary>${msg('edc.enrol.cannotScan')}</summary>
                <code id="edc-setup-key"></code>
            </details>
            <#-- Must come before edc-enrol.js, which renders the QR with it on load. This template
                 also serves the email step, which has no QR, so it is only pulled in here. -->
            <script src="${url.resourcesPath}/js/qr-code-styling-1.9.2.js"></script>
        </#if>

        <form id="edc-enrol-form" action="${url.loginAction}" method="post">
            <label class="edc-visually-hidden" for="edc-code-input">${msg('edc.enrol.codePrompt')}</label>
            <div class="edc-otp-boxes" id="edc-code-boxes" data-length="${codeLength?c}">
                <#list 1..codeLength as _>
                    <input class="edc-otp-box" type="text" inputmode="numeric" pattern="[0-9]*"
                           maxlength="1" autocomplete="off"/>
                </#list>
            </div>
            <#-- The boxes are decorative: edc-enrol.js mirrors them into this field, which is what
                 actually posts. privacyIDEA reads it exactly as it reads the sign-in code. -->
            <input id="otp" name="otp" type="password" class="edc-otp-hidden" aria-hidden="true"
                   tabindex="-1" value="" autocomplete="new-password"/>

            <div class="${properties.kcFormGroupClass!}">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} edc-primary" type="submit" id="edc-verify">
                    ${msg('edc.enrol.verify')}
                </button>
                <div class="${properties.kcFormOptionsWrapperClass!}">
                    <span>
                        <button type="submit" name="back" value="1" class="edc-link-button">
                            ${msg('edc.enrol.chooseDifferent')}
                        </button>
                    </span>
                </div>
            </div>
        </form>

        <script src="${url.resourcesPath}/js/edc-enrol.js"></script>
    </#if>
</@layout.registrationLayout>
