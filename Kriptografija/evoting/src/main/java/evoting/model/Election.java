package evoting.model;

import java.time.LocalDateTime;
import java.util.List;

public class Election {

    public enum Status { PENDING, ACTIVE, CLOSED, COUNTED }

    private final String        id;
    private final String        title;
    private final String        description;
    private final List<String>  options;
    private final LocalDateTime startTime;
    private final LocalDateTime endTime;
    private final String        organizerUsername;
    private       Status        status;

    public Election(String id, String title, String description,
                    List<String> options,
                    LocalDateTime startTime, LocalDateTime endTime,
                    String organizerUsername) {
        this.id                = id;
        this.title             = title;
        this.description       = description;
        this.options           = options;
        this.startTime         = startTime;
        this.endTime           = endTime;
        this.organizerUsername = organizerUsername;
        this.status            = Status.PENDING;
    }

    public Status computeStatus() {
        LocalDateTime now = LocalDateTime.now();
        if (status == Status.COUNTED)  return Status.COUNTED;
        if (now.isBefore(startTime))   return Status.PENDING;
        if (now.isAfter(endTime))      return Status.CLOSED;
        return Status.ACTIVE;
    }

    public String        getId()                { return id; }
    public String        getTitle()             { return title; }
    public String        getDescription()       { return description; }
    public List<String>  getOptions()           { return options; }
    public LocalDateTime getStartTime()         { return startTime; }
    public LocalDateTime getEndTime()           { return endTime; }
    public String        getOrganizerUsername() { return organizerUsername; }
    public Status        getStatus()            { return status; }
    public void          setStatus(Status s)    { this.status = s; }
}
