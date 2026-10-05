package com.khalibre.keycloak.provider.telegram.bot;

public enum TelegramBotMode {

    POLLING("polling"),
    WEBHOOK("webhook");

    private final String value;

    TelegramBotMode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static TelegramBotMode fromString(String value) {
        for (TelegramBotMode mode : values()) {
            if (mode.value.equalsIgnoreCase(value)) {
                return mode;
            }
        }
        return POLLING;
    }
}
