<#ftl output_format="plainText">
${msg("otpEmailBrand")}
${msg("otpEmailBrandSubtitle")}

${msg("otpEmailHeading")}

${msg("otpEmailIntro", user.firstname?has_content?then(user.firstname, user.username), appName)}

${msg("otpEmailCodeLabel")}: ${otp}

${msg("otpEmailValid", expiryMinutes)}
${msg("otpEmailRequestedAt", requestDate, requestTime, clientIp)}

${msg("otpEmailNotice")}

${msg("otpEmailFooterAutomated")}
${msg("otpEmailFooterOrg")}