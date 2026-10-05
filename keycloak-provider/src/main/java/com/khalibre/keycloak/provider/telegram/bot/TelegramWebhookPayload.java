package com.khalibre.keycloak.provider.telegram.bot;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TelegramWebhookPayload {

    @JsonProperty("update_id")
    private Long updateId;

    @JsonProperty("message")
    private Message message;

    public Long getUpdateId() { return updateId; }
    public Message getMessage() { return message; }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Message {
        @JsonProperty("message_id")
        private Long messageId;

        @JsonProperty("from")
        private From from;

        @JsonProperty("chat")
        private Chat chat;

        @JsonProperty("date")
        private Long date;

        @JsonProperty("text")
        private String text;

        @JsonProperty("contact")
        private Contact contact;

        public Long getMessageId() { return messageId; }
        public From getFrom() { return from; }
        public Chat getChat() { return chat; }
        public Long getDate() { return date; }
        public String getText() { return text; }
        public Contact getContact() { return contact; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class From {
        @JsonProperty("id")
        private String id;

        @JsonProperty("is_bot")
        private boolean isBot;

        @JsonProperty("first_name")
        private String firstName;

        @JsonProperty("last_name")
        private String lastName;

        @JsonProperty("username")
        private String username;

        @JsonProperty("language_code")
        private String languageCode;

        public String getId() { return String.valueOf(id); }
        public boolean isBot() { return isBot; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
        public String getUsername() { return username; }
        public String getLanguageCode() { return languageCode; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Chat {
        @JsonProperty("id")
        private String id;

        @JsonProperty("first_name")
        private String firstName;

        @JsonProperty("last_name")
        private String lastName;

        @JsonProperty("username")
        private String username;

        @JsonProperty("type")
        private String type;

        public String getId() { return String.valueOf(id); }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
        public String getUsername() { return username; }
        public String getType() { return type; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Contact {
        @JsonProperty("phone_number")
        private String phoneNumber;

        @JsonProperty("user_id")
        private Long userId;

        @JsonProperty("first_name")
        private String firstName;

        @JsonProperty("last_name")
        private String lastName;

        @JsonProperty("vcard")
        private String vcard;

        public String getPhoneNumber() { return phoneNumber; }
        public Long getUserId() { return userId; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
    }
}
