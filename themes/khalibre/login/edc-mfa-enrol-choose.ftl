<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg('edc.enrol.chooseTitle')}
    <#elseif section = "form">
        <#assign selectedChannel = "">
        <#if telegramAvailable && !telegramConfigured && telegramRecommended>
            <#assign selectedChannel = "telegram">
        <#elseif totpAvailable && !totpConfigured>
            <#assign selectedChannel = "totp">
        <#elseif emailAvailable && !emailConfigured && hasEmailAddress>
            <#assign selectedChannel = "email">
        <#elseif telegramAvailable && !telegramConfigured>
            <#assign selectedChannel = "telegram">
        </#if>

        <#if error??>
            <#if error = "edc.enrol.channelSetupNextRequired">
                <div class="edc-alert" role="alert" style="background: #e6f4ea; border-color: #34a853; color: #137333;">
                    <span>${msg(error)}</span>
                </div>
            <#else>
                <div class="edc-alert" role="alert">
                    <span>${msg(error!'')}</span>
                </div>
            </#if>
        </#if>
        <p class="edc-otp-subtitle">${msg('edc.enrol.chooseIntro')}</p>

        <#-- Saying why a channel is unavailable matters more than hiding it. This is a
             deployment where most staff have no email address at all: offering email and then
             sending nothing is how a mandated change turns into a queue at the ICT desk. -->
        <#if !hasEmailAddress && telegramAvailable>
            <div class="edc-note-info">
                <span>${msg('edc.enrol.noEmailNote')}</span>
            </div>
        </#if>
        <#-- One dead-end message, not two. A second alert used to fire on
             "!telegramAvailable && !emailAvailable && totpAvailable" - which is precisely the case
             where the authenticator app IS the one option on screen. It told a user who was looking at
             a working row that "No verification channel can be set up on this account", which is the
             one thing the page could not have meant: it is what a per-application policy restricting
             an application to the authenticator app produces, so every administrator who switched
             Telegram and Email off saw a user told there was nothing to do while sitting in front of
             the one channel that was available.
             There is no second reason to distinguish. Anything still available is offered; when
             nothing is, "every method has been switched off" is the accurate account of it, and a
             user with no address of their own is already covered by the note above. -->
        <#if !anyChannelAvailable>
            <div class="edc-alert" role="alert">
                <span>${msg('edc.enrol.allChannelsDisabled')}</span>
            </div>
        </#if>

        <#if anyChannelAvailable>
        <form id="edc-enrol-form" action="${url.loginAction}" method="post">
            <div class="edc-channels edc-channels-lg" role="radiogroup"
                 aria-label="${msg('edc.enrol.chooseIntro')}">
                <#if telegramAvailable>
                    <label class="edc-option<#if telegramConfigured> edc-option-configured</#if>">
                        <span class="edc-channel-ico">
                            <img src="${url.resourcesPath}/img/telegram.svg" width="18" height="18" alt="">
                        </span>
                        <span class="edc-channel-body">
                            <span class="edc-channel-name">
                                ${msg('edc.enrol.telegram')}
                                <#if telegramConfigured>
                                    <span class="edc-tag edc-tag-configured">${msg('edc.enrol.configured')}</span>
                                <#elseif telegramRecommended>
                                    <span class="edc-tag">${msg('edc.enrol.recommended')}</span>
                                </#if>
                                <#if requiredChannels?seq_contains("telegram")>
                                    <span class="edc-tag edc-tag-required">${msg('edc.enrol.required')}</span>
                                </#if>
                            </span>
                            <span class="edc-channel-detail">${msg('edc.enrol.telegramDetail')}</span>
                        </span>
                        <input class="edc-option-input" type="radio" name="channel" value="telegram"
                               <#if telegramConfigured>disabled<#elseif selectedChannel = "telegram">checked</#if>>
                    </label>
                </#if>

                <#if totpAvailable>
                <label class="edc-option<#if totpConfigured> edc-option-configured</#if>">
                    <span class="edc-channel-ico">
                        <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
                             stroke-width="2" aria-hidden="true">
                            <rect x="7" y="2" width="10" height="20" rx="2"></rect>
                            <path d="M11 18h2"></path>
                        </svg>
                    </span>
                    <span class="edc-channel-body">
                        <span class="edc-channel-name">
                            ${msg('edc.enrol.totp')}
                            <#if totpConfigured>
                                <span class="edc-tag edc-tag-configured">${msg('edc.enrol.configured')}</span>
                            </#if>
                            <#if requiredChannels?seq_contains("totp")>
                                <span class="edc-tag edc-tag-required">${msg('edc.enrol.required')}</span>
                            </#if>
                        </span>
                        <span class="edc-channel-detail">${msg('edc.enrol.totpDetail')}</span>
                    </span>
                    <input class="edc-option-input" type="radio" name="channel" value="totp"
                           <#if totpConfigured>disabled<#elseif selectedChannel = "totp">checked</#if>>
                </label>
                </#if>

                <#-- Permission and address are different questions. No address is this person's own
                     problem and the row explains it; switched off is an administrator's decision, so
                     the row is simply not drawn. -->
                <#if emailAvailable>
                <label class="edc-option<#if !hasEmailAddress> edc-option-off<#elseif emailConfigured> edc-option-configured</#if>">
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
                            <#if emailConfigured>
                                <span class="edc-tag edc-tag-configured">${msg('edc.enrol.configured')}</span>
                            </#if>
                            <#if requiredChannels?seq_contains("email")>
                                <span class="edc-tag edc-tag-required">${msg('edc.enrol.required')}</span>
                            </#if>
                            <#if !hasEmailAddress>
                                <span class="edc-tag edc-tag-off">${msg('edc.enrol.unavailable')}</span>
                            </#if>
                        </span>
                        <span class="edc-channel-detail">
                            <#if hasEmailAddress>${msg('edc.enrol.emailDetail')}<#else>${msg('edc.enrol.noEmailDetail')}</#if>
                        </span>
                    </span>
                    <input class="edc-option-input" type="radio" name="channel" value="email"
                           <#if !hasEmailAddress || emailConfigured>disabled<#elseif selectedChannel = "email">checked</#if>>
                </label>
                </#if>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} edc-primary" type="submit" id="edc-enrol-continue">
                    ${msg('edc.enrol.continue')}
                </button>
            </div>
        </form>
        </#if>
    </#if>
</@layout.registrationLayout>