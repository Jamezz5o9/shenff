package org.taskspace.notificationmanagement.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.thymeleaf.context.Context;

@Getter
@Setter
@Builder
@AllArgsConstructor
@RequiredArgsConstructor
public class NotificationRequest {
    private String to;

    private String subject;

    private String content;

    private String message;

    @NotBlank(message = "Receiver Email address can not be blank")
    @Email(regexp = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$")
    private String sender;

    private Context context;
}