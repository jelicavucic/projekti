package evoting.model;

public class Vote {

    private final String voteId;
    private final String electionId;
    private final String voterUsername;
    private final byte[] encryptedVote;
    private final byte[] encryptedAesKey;
    private final byte[] iv;
    private final byte[] signature;
    private final String voteHash;

    public Vote(String voteId, String electionId, String voterUsername,
                byte[] encryptedVote, byte[] encryptedAesKey,
                byte[] iv, byte[] signature, String voteHash) {
        this.voteId          = voteId;
        this.electionId      = electionId;
        this.voterUsername   = voterUsername;
        this.encryptedVote   = encryptedVote;
        this.encryptedAesKey = encryptedAesKey;
        this.iv              = iv;
        this.signature       = signature;
        this.voteHash        = voteHash;
    }

    public String getId()              { return voteId; }
    public String getElectionId()      { return electionId; }
    public String getVoterUsername()   { return voterUsername; }
    public byte[] getEncryptedVote()   { return encryptedVote; }
    public byte[] getEncryptedAesKey() { return encryptedAesKey; }
    public byte[] getIv()              { return iv; }
    public byte[] getSignature()       { return signature; }
    public String getVoteHash()        { return voteHash; }
}
