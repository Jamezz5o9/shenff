package org.taskspace.notificationmanagement.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
public class MailConfig {

    @Value("${MAIL_HOST:smtp.gmail.com}")
    private String host;

    @Value("${MAIL_PORT:465}")
    private int port;

    @Value("${MAIL_USERNAME:lekan.sofuyi@gmail.com}")
    private String username;

    @Value("${MAIL_PASSWORD:zehsiziiaifdzogy}")
    private String password;

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.starttls.enable", true);
        props.put("mail.smtp.auth", true);
        props.put("mail.smtp.timeout", "3000");
        props.put("mail.smtp.connectiontimeout", "5000");
        props.put("mail.smtp.writetimeout", "5000");
        props.put("mail.smtp.ssl.enable", true);
        return mailSender;
    }
}