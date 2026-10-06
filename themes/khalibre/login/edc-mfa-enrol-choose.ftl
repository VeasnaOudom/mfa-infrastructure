<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg('edc.enrol.chooseTitle')}
    <#elseif section = "form">
        <#if error??>
            <div class="edc-alert" role="alert">
                <span>${msg(error!'')}</span>
            </div>
        </#if>
        <p class="edc-otp-subtitle">${msg('edc.enrol.chooseIntro')}</p>

        <#-- Saying why a channel is unavailable matters more than hiding it. This is a
             deployment where most staff have no email address at all: offering email and then
             sending nothing is how a mandated change turns into a queue at the ICT desk. -->
        <#if !emailAvailable && telegramAvailable>
            <div class="edc-note-info">
                <span>${msg('edc.enrol.noEmailNote')}</span>
            </div>
        </#if>
        <#if !telegramAvailable && !emailAvailable>
            <div class="edc-alert" role="alert">
                <span>${msg('edc.enrol.noChannelConfigured')}</span>
            </div>
        </#if>

        <form id="edc-enrol-form" action="${url.loginAction}" method="post">
            <div class="edc-channels edc-channels-lg" role="radiogroup"
                 aria-label="${msg('edc.enrol.chooseIntro')}">
                <#if telegramAvailable>
                    <label class="edc-option">
                        <span class="edc-channel-ico">
                            <img src="${url.resourcesPath}/img/telegram.svg" width="18" height="18" alt="">
                        </span>
                        <span class="edc-channel-body">
                            <span class="edc-channel-name">
                                ${msg('edc.enrol.telegram')}
                                <#if telegramRecommended>
                                    <span class="edc-tag">${msg('edc.enrol.recommended')}</span>
                                </#if>
                            </span>
                            <span class="edc-channel-detail">${msg('edc.enrol.telegramDetail')}</span>
                        </span>
                        <input class="edc-option-input" type="radio" name="channel" value="telegram"
                               <#if telegramRecommended>checked</#if>>
                    </label>
                </#if>

                <label class="edc-option">
                    <span class="edc-channel-ico">
                        <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
                             stroke-width="2" aria-hidden="true">
                            <rect x="7" y="2" width="10" height="20" rx="2"></rect>
                            <path d="M11 18h2"></path>
                        </svg>
                    </span>
                    <span class="edc-channel-body">
                        <span class="edc-channel-name">${msg('edc.enrol.totp')}</span>
                        <span class="edc-channel-detail">${msg('edc.enrol.totpDetail')}</span>
                    </span>
                    <input class="edc-option-input" type="radio" name="channel" value="totp"
                           <#if !telegramAvailable>checked</#if>>
                </label>

                <label class="edc-option<#if !emailAvailable> edc-option-off</#if>">
                    <span class="edc-channel-ico">
                        <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
                             stroke-width="2" aria-hidden="true">
                            <rect x="2" y="4" width="20" height="16" rx="2"></rect>
                            <path d="m2 7 10 7 10-7"></path>
                        </svg>
                    </span>
                    <span class="edc-channel-body">
                        <span class="edc-channel-name">
                            ${msg('edc.enrol.email')}
                            <#if !emailAvailable>
                                <span class="edc-tag edc-tag-off">${msg('edc.enrol.unavailable')}</span>
                            </#if>
                        </span>
                        <span class="edc-channel-detail">
                            <#if emailAvailable>${msg('edc.enrol.emailDetail')}<#else>${msg('edc.enrol.noEmailDetail')}</#if>
                        </span>
                    </span>
                    <input class="edc-option-input" type="radio" name="channel" value="email"
                           <#if !emailAvailable>disabled</#if>>
                </label>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} edc-primary" type="submit" id="edc-enrol-continue">
                    ${msg('edc.enrol.continue')}
                </button>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>