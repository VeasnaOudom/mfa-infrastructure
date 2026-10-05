<#ftl output_format="plainText">
${msg("resetEmailTextBrand")}

${msg("resetEmailHeading")}

${msg("resetEmailIntro", user.firstname?has_content?then(user.firstname, user.username), realmName)}

${msg("resetEmailAction")}: ${link}

${msg("resetEmailExpiry", linkExpirationFormatter(linkExpiration))}

${msg("resetEmailTextNotice")}

--
${msg("otpEmailFooterAutomated")}
${msg("otpEmailFooterOrg")}