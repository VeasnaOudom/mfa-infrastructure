<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg('edc.enrol.telegramTitle')}
    <#elseif section = "form">
        <script src="${url.resourcesPath}/js/qr-code-styling-1.9.2.js"></script>
        <#if error??>
            <div class="edc-alert" role="alert">
                <span>${msg(error!'')}</span>
            </div>
        </#if>
        <div id="edc-enrol-telegram" data-failed="${msg('edc.enrol.telegramFailed')}">
            <p class="edc-otp-subtitle">${msg('edc.enrol.telegramIntro')}</p>

            <div id="edc-qr" class="edc-qr"></div>

            <p class="edc-waiting" id="edc-waiting">
                ${msg('edc.enrol.waitingScan')} <b id="edc-telegram-timer">1:00</b>
            </p>

            <p class="edc-waiting">
                ${msg('edc.enrol.openTelegram')}
                <a id="edc-telegram-link" href="#" target="_blank" rel="noopener">${msg('doClickHere')}</a>
            </p>

            <div class="edc-note-info" id="edc-phone-prompt" hidden>
                <span>${msg('edc.enrol.phonePrompt')}</span>
            </div>
            <#-- Telegram answers a scan by long polling, so a slow connection produces silence.
                 Shown only if the scan has not registered after a few seconds. -->
            <div class="edc-note-info" id="edc-slow-hint" hidden>
                <span>${msg('edc.enrol.stillWaiting')}</span>
            </div>
            <#-- Filled in by edc-enrol.js when the scan fails in the browser, so the wording lives in
                 one place rather than being written into the page as a hidden span. -->
            <div class="edc-alert" id="edc-telegram-error" hidden role="alert"></div>

            <form id="edc-enrol-form" action="${url.loginAction}" method="post">
                <div class="${properties.kcFormGroupClass!}">
                    <#-- Hidden until the link is written: a Continue button that does nothing for the
                         minute it takes to scan a code reads as broken. -->
                    <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} edc-primary" type="submit"
                            id="edc-telegram-continue" hidden>
                        ${msg('edc.enrol.continue')}
                    </button>
                </div>
            </form>

            <div class="${properties.kcFormOptionsWrapperClass!}">
                <span>
                    <button type="submit" name="back" value="1" form="edc-enrol-form"
                            class="edc-link-button" id="edc-telegram-back">
                        ${msg('edc.enrol.chooseDifferent')}
                    </button>
                </span>
            </div>

            <script>
                window.edcEnrolTelegram = {
                    qrUrl: "${telegramQrUrl}",
                    statusUrl: "${telegramStatusUrl}",
                    initUrl: "${telegramInitUrl}",
                    phoneUrl: "${telegramPhoneUrl}",
                    linkUrl: "${telegramLinkUrl}",
                    resourcesPath: "${url.resourcesPath}"
                };
            </script>
        </div>
        <script src="${url.resourcesPath}/js/edc-enrol.js"></script>
    </#if>
</@layout.registrationLayout>