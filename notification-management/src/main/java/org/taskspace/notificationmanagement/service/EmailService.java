package org.taskspace.notificationmanagement.service;

import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.notificationmanagement.dto.response.NotificationResponse;

import java.util.concurrent.CompletableFuture;

public interface EmailService {
    CompletableFuture<NotificationResponse> sendEmail(NotificationRequest request);
}
