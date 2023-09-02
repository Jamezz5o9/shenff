package org.taskspace.usermanagement.utils.utils;

import java.util.UUID;

public class UserUtility {
    public static String generateUserId() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString().replace("-", "");
    }
}
