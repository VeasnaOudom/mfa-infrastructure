<#import "template.ftl" as layout>
<#--
  EDC-styled reset password email.

  Keycloak's stock template renders a bare paragraph with a default-styled link, which is why this
  file exists. It deliberately mirrors privacyidea-otp.ftl so both transactional emails share one
  look: same navy brand header, same card, same advisory and footer treatment.

  Unlike the OTP email, this one is sent by Keycloak's own ResetCredentialEmail, so the
  otpEmailBaseUrl attribute our provider injects is not available here. The origin therefore comes
  from theme.properties (emailBaseUrl), which is deployed per environment, with a text-only brand
  fallback so a missing value degrades gracefully instead of breaking the email.
-->
<@layout.emailLayout>
<style>
@font-face{font-family:'Plus Jakarta Sans';font-style:normal;font-weight:200 800;font-display:swap;src:url('${msg('otpEmailFontUrl')}') format('woff2');}
</style>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f9;padding:28px 14px;font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <tr>
    <td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background-color:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #d7dae2;box-shadow:0 10px 30px rgba(20,22,43,0.08);">
        <tr>
          <td style="background-color:#2b3072;padding:26px 34px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <#-- emailBaseUrl is rendered into this theme's theme.properties by the
                    generate_creds role from keycloak_public_base_url. Guarded so a missing
                    property degrades to text branding rather than a broken image URL. -->
                <#if (properties.emailBaseUrl!'')?? && (properties.emailBaseUrl!'')?has_content>
                  <td width="64" valign="middle" style="width:64px;">
                    <img src="${properties.emailBaseUrl}${url.resourcesPath}/img/edc-logo-white.png" alt="logo" width="60" height="60" style="width:60px;height:60px;border-radius:50%;display:block;"/>
                  </td>
                  <td valign="middle" style="padding-left:14px;">
                    <div style="font-size:21px;font-weight:700;color:#ffffff;letter-spacing:0.2px;line-height:1.25;">${msg("otpEmailBrand")}</div>
                    <div style="font-size:12px;font-weight:600;color:#c3caea;letter-spacing:2px;padding-top:4px;">${msg("otpEmailBrandSubtitle")}</div>
                  </td>
                <#else>
                  <td valign="middle">
                    <div style="font-size:21px;font-weight:700;color:#ffffff;letter-spacing:0.2px;line-height:1.25;">${msg("otpEmailBrand")}</div>
                    <div style="font-size:12px;font-weight:600;color:#c3caea;letter-spacing:2px;padding-top:4px;">${msg("otpEmailBrandSubtitle")}</div>
                  </td>
                </#if>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:34px 38px 0 38px;">
            <h1 style="margin:0;font-size:27px;font-weight:700;color:#14162b;line-height:1.25;letter-spacing:-0.3px;">${msg("resetEmailHeading")}</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:14px 38px 0 38px;">
            <p style="margin:0;font-size:16px;color:#5b6478;line-height:1.6;">${msg("resetEmailIntro", user.firstname?has_content?then(user.firstname, user.username), realmName)}</p>
          </td>
        </tr>
        <tr>
          <td align="center" style="padding:28px 38px 0 38px;">
            <!--[if mso]>
            <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
                         href="${link}" style="height:50px;v-text-anchor:middle;width:260px;" arcsize="12%" stroke="f" fillcolor="#2b3072">
              <w:anchorlock/><center style="color:#ffffff;font-family:Helvetica,Arial,sans-serif;font-size:16px;font-weight:bold;">${msg("resetEmailAction")}</center>
            </v:roundrect>
            <![endif]-->
            <!--[if !mso]><!-->
            <a href="${link}" style="display:inline-block;background-color:#2b3072;color:#ffffff;font-size:16px;font-weight:600;letter-spacing:0.2px;text-decoration:none;padding:15px 34px;border-radius:8px;">${msg("resetEmailAction")}</a>
            <!--<![endif]-->
          </td>
        </tr>
        <tr>
          <td style="padding:22px 38px 0 38px;">
            <p style="margin:0;font-size:15px;color:#5b6478;line-height:1.6;">${msg("resetEmailExpiry", linkExpirationFormatter(linkExpiration))}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 38px 0 38px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fdf7e6;border-left:3px solid #d9a300;border-radius:8px;">
              <tr>
                <td style="padding:16px 18px;font-size:15px;color:#14162b;line-height:1.6;">${msg("resetEmailNotice")}</td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:28px 38px 34px 38px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #d7dae2;">
              <tr>
                <td style="padding-top:22px;font-size:13px;color:#8b94a7;line-height:1.7;">${msg("otpEmailFooterAutomated")}<br/>${msg("otpEmailFooterOrg")}</td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</@layout.emailLayout>