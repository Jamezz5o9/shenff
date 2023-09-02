package org.taskspace.taskmanagement.utils;

import java.util.UUID;

public class TaskUtils {
    public static String generateTaskId() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString().replace("-", "");
    }
}