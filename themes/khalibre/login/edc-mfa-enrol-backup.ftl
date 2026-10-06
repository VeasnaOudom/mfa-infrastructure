<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg('edc.enrol.backupTitle')}
    <#elseif section = "form">
        <p class="edc-otp-subtitle">${msg('edc.enrol.backupIntro')}</p>

        <#-- Read out in two columns so ten codes are scannable on a phone screen. The list is
             rendered server-side and never returned again: privacyIDEA keeps only hashes, so this
             page is the one and only time these codes exist. -->
        <div class="edc-codes" id="edc-codes" role="list">
            <#list backupCodes as code>
                <span class="edc-code" role="listitem">${code}</span>
            </#list>
        </div>

        <div class="edc-note">
            <strong>${msg('edc.enrol.backupNoteTitle')}</strong>
            <span>${msg('edc.enrol.backupNote')}</span>
        </div>

        <form id="edc-enrol-form" action="${url.loginAction}" method="post">
            <div class="edc-actions">
                <button type="button" class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} edc-secondary"
                        id="edc-codes-download"
                        data-filename="${realm.name}-backup-codes.txt">
                    ${msg('edc.enrol.download')}
                </button>
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} edc-primary" type="submit" id="edc-codes-continue">
                    ${msg('edc.enrol.saved')}
                </button>
            </div>
        </form>

        <script src="${url.resourcesPath}/js/edc-enrol.js"></script>
    </#if>
</@layout.registrationLayout>