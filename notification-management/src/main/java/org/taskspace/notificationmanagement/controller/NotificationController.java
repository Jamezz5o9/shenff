package org.taskspace.notificationmanagement.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.notificationmanagement.dto.response.NotificationResponse;
import org.taskspace.notificationmanagement.service.EmailService;

import java.util.concurrent.CompletableFuture;

@Component
@RequiredArgsConstructor
public class NotificationController {

    private final EmailService emailService;
    public NotificationResponse sendEmail(NotificationRequest request) {
        CompletableFuture<NotificationResponse> enquiryFuture = emailService.sendEmail(request);
        return enquiryFuture.join();
    }
}