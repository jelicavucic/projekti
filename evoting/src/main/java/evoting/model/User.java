package evoting.model;

public class User {

    public enum Role { ORGANIZER, VOTER }

    private final String username;
    private final String passwordHash;
    private final Role   role;

    private final String orgName;
    private final String orgId;
    private final String firstName;
    private final String lastName;

    private int     failedLogins;
    private boolean revoked;

    public User(String username, String passwordHash,
                String orgName, String orgId) {
        this.username     = username;
        this.passwordHash = passwordHash;
        this.role         = Role.ORGANIZER;
        this.orgName      = orgName;
        this.orgId        = orgId;
        this.firstName    = null;
        this.lastName     = null;
        this.failedLogins = 0;
        this.revoked      = false;
    }

    public User(String username, String passwordHash,
                String firstName, String lastName, boolean isVoter) {
        this.username     = username;
        this.passwordHash = passwordHash;
        this.role         = Role.VOTER;
        this.firstName    = firstName;
        this.lastName     = lastName;
        this.orgName      = null;
        this.orgId        = null;
        this.failedLogins = 0;
        this.revoked      = false;
    }

    public String  getUsername()     { return username; }
    public String  getPasswordHash() { return passwordHash; }
    public Role    getRole()         { return role; }
    public String  getOrgName()      { return orgName; }
    public String  getOrgId()        { return orgId; }
    public String  getFirstName()    { return firstName; }
    public String  getLastName()     { return lastName; }
    public int     getFailedLogins() { return failedLogins; }
    public boolean isRevoked()       { return revoked; }
    public boolean isOrganizer()     { return role == Role.ORGANIZER; }
    public boolean isVoter()         { return role == Role.VOTER; }

    public void incrementFailedLogins() { failedLogins++; }
    public void resetFailedLogins()     { failedLogins = 0; }
    public void revoke()                { revoked = true; }
}
