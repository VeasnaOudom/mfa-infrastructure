<#import "template.ftl" as layout>
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
                <td width="64" valign="middle" style="width:64px;">
                  <img src="${msg('otpEmailLogoUrl')}" alt="" width="60" height="60" style="width:60px;height:60px;border-radius:50%;display:block;"/>
                </td>
                <td valign="middle" style="padding-left:14px;">
                  <div style="font-size:21px;font-weight:700;color:#ffffff;letter-spacing:0.2px;line-height:1.25;">${msg("otpEmailBrand")}</div>
                  <div style="font-size:12px;font-weight:600;color:#c3caea;letter-spacing:2px;padding-top:4px;">${msg("otpEmailBrandSubtitle")}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:34px 38px 0 38px;">
            <h1 style="margin:0;font-size:27px;font-weight:700;color:#14162b;line-height:1.25;letter-spacing:-0.3px;">${msg("otpEmailHeading")}</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:14px 38px 0 38px;">
            <p style="margin:0;font-size:16px;color:#5b6478;line-height:1.6;">${msg("otpEmailIntro", user.firstname?has_content?then(user.firstname, user.username))} <b>${appName}</b>.</p>
          </td>
        </tr>
        <tr>
          <td style="padding:26px 38px 0 38px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#eef0fb;border:1px solid #b9bfee;border-radius:12px;">
              <tr>
                <td align="center" style="padding:26px 16px 28px 16px;">
                  <div style="font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:40px;font-weight:700;letter-spacing:14px;color:#2b3072;line-height:1.1;">${otpFormatted}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 38px 0 38px;">
            <p style="margin:0;font-size:16px;color:#14162b;line-height:1.6;">${msg("otpEmailValid", expiryMinutes)}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 38px 0 38px;">
            <p style="margin:0;font-size:15px;color:#5b6478;line-height:1.6;">${msg("otpEmailRequestedAt", requestDate, requestTime, clientIp)}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 38px 0 38px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fdf7e6;border-left:3px solid #d9a300;border-radius:8px;">
              <tr>
                <td style="padding:16px 18px;font-size:15px;color:#14162b;line-height:1.6;">${msg("otpEmailNotice")}</td>
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