package org.taskspace.gateway.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ApiResponse {
    private final boolean isSuccessful;

    @JsonFormat(pattern="yyyy-MM-dd HH:mm:ss")
    private final LocalDateTime timeStamp;

    private final Object data;

    public ApiResponse(boolean isSuccessful, Object data) {
        this.isSuccessful = isSuccessful;
        this.data = data;
        timeStamp = LocalDateTime.now();
    }
}