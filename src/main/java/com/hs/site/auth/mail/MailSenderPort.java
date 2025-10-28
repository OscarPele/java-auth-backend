package com.hs.site.auth.mail;

public interface MailSenderPort {
    void send(String to, String subject, String htmlBody);
}
