package org.taskspace.taskmanagement.data.request;

import lombok.Data;

@Data
public class TaskRequest {

    private String taskTitle;

    private String taskBody;

    private String taskPriority;

}