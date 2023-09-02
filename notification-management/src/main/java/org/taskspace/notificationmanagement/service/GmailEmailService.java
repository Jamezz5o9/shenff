package org.taskspace.notificationmanagement.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.notificationmanagement.dto.response.NotificationResponse;
import org.taskspace.notificationmanagement.exception.TaskSpaceNotificationException;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CompletableFuture;

import static org.taskspace.notificationmanagement.utils.AppConstant.TASKSPACE_EMAIL;
import static org.taskspace.notificationmanagement.utils.AppConstant.TASKSPACE_USERNAME;

@Service
@RequiredArgsConstructor
public class GmailEmailService implements EmailService {
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine templateEngine;
    @Override
    public CompletableFuture<NotificationResponse> sendEmail(NotificationRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String emailContent = templateEngine.process(request.getContent(), request.getContext());
                MimeMessage mailMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mailMessage, "utf-8");
                mimeMessageHelper.setSubject(request.getSubject());
                mimeMessageHelper.setTo(request.getTo());
                mimeMessageHelper.setFrom(new InternetAddress(TASKSPACE_EMAIL, TASKSPACE_USERNAME));
                mimeMessageHelper.setText(emailContent, true);
                javaMailSender.send(mailMessage);
                return new NotificationResponse(String.format("Email sent successfully to %s", request.getTo() ));
            } catch (MessagingException | MailException | UnsupportedEncodingException exception) {
                throw new TaskSpaceNotificationException(exception.getMessage());
            }
        });
    }
}
