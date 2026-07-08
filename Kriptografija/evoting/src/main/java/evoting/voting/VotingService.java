package evoting.voting;

import evoting.crypto.CryptoService;
import evoting.model.Election;
import evoting.model.User;
import evoting.model.Vote;
import evoting.storage.ElectionStore;
import evoting.storage.UserStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class VotingService {

    private final ElectionStore electionStore;
    private final UserStore     userStore;

    public VotingService(ElectionStore electionStore, UserStore userStore) {
        this.electionStore = electionStore;
        this.userStore     = userStore;
    }

    public void createElection(User organizer, String title, String description,
                                List<String> options,
                                LocalDateTime start, LocalDateTime end) throws Exception {
        if (options.size() < 2 || options.size() > 5)
            throw new Exception("broj opcija mora biti između 2 i 5");
        if (end.isBefore(start))
            throw new Exception("kraj mora biti nakon početka");

        String   id       = "election_" + System.currentTimeMillis();
        Election election = new Election(id, title, description,
                options, start, end, organizer.getUsername());
        electionStore.saveElection(election);
        System.out.println("glasanje kreirano: " + id);
    }

    public String castVote(User voter, Election election,
                            int optionIndex, PrivateKey voterPrivateKey) throws Exception {
        if (election.computeStatus() != Election.Status.ACTIVE)
            throw new Exception("glasanje nije aktivno");
        if (electionStore.hasVoted(election.getId(), voter.getUsername()))
            throw new Exception("već ste glasali");

        String chosenOption = election.getOptions().get(optionIndex);

        KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
        kg.init(256, new SecureRandom());
        SecretKey aesKey = kg.generateKey();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] encryptedVote = aesCipher.doFinal(chosenOption.getBytes("UTF-8"));

        X509Certificate orgCert = userStore.loadCertificate(election.getOrganizerUsername());
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, orgCert.getPublicKey());
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        Signature sig = Signature.getInstance("SHA256WithRSA", "BC");
        sig.initSign(voterPrivateKey);
        sig.update(encryptedVote);
        byte[] signature = sig.sign();

        MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
        String voteHash = CryptoService.bytesToHex(md.digest(encryptedVote));

        String voteId = voter.getUsername() + "_" + System.currentTimeMillis();
        Vote   vote   = new Vote(voteId, election.getId(), voter.getUsername(),
                encryptedVote, encryptedAesKey, iv, signature, voteHash);
        electionStore.saveVote(vote);

        System.out.println("glas upisan.");
        return voteHash;
    }

    public boolean verifyVote(String electionId, String voterUsername,
                               String voteHash, PublicKey voterPublicKey) throws Exception {
        List<Vote> votes = electionStore.loadAllVotes(electionId);
        for (Vote vote : votes) {
            if (!vote.getVoterUsername().equals(voterUsername)) continue;
            if (!vote.getVoteHash().equals(voteHash)) continue;

            Signature sig = Signature.getInstance("SHA256WithRSA", "BC");
            sig.initVerify(voterPublicKey);
            sig.update(vote.getEncryptedVote());
            return sig.verify(vote.getSignature());
        }
        return false;
    }

    public Map<String, Integer> countVotes(Election election,
                                            PrivateKey organizerPrivateKey) throws Exception {
        Election.Status status = election.computeStatus();
        if (status != Election.Status.CLOSED && status != Election.Status.COUNTED)
            throw new Exception("glasanje još nije završeno");

        List<Vote>          votes   = electionStore.loadAllVotes(election.getId());
        Map<String, Integer> results = new LinkedHashMap<>();
        for (String opt : election.getOptions()) results.put(opt, 0);

        for (Vote vote : votes) {
            try {
                Cipher rsaCipher = Cipher.getInstance(
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
                rsaCipher.init(Cipher.DECRYPT_MODE, organizerPrivateKey);
                byte[] aesKeyBytes = rsaCipher.doFinal(vote.getEncryptedAesKey());

                SecretKey aesKey   = new SecretKeySpec(aesKeyBytes, "AES");
                Cipher    aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey,
                        new IvParameterSpec(vote.getIv()));
                String chosenOption = new String(
                        aesCipher.doFinal(vote.getEncryptedVote()), "UTF-8");

                results.merge(chosenOption, 1, Integer::sum);
            } catch (Exception e) {
                System.out.println("upozorenje: nije moguće dešifrovati " + vote.getId());
            }
        }

        election.setStatus(Election.Status.COUNTED);
        electionStore.saveElection(election);
        return results;
    }

    public String generateReport(Election election,
                                  Map<String, Integer> results,
                                  PrivateKey organizerPrivateKey) throws Exception {
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder sb = new StringBuilder();
        sb.append("=== IZVJEŠTAJ O GLASANJU ===\n");
        sb.append("naslov   : ").append(election.getTitle()).append("\n");
        sb.append("period   : ").append(election.getStartTime())
          .append(" — ").append(election.getEndTime()).append("\n");
        sb.append("generisan: ").append(timestamp).append("\n");
        sb.append("---------------------------\n");

        int total = results.values().stream().mapToInt(i -> i).sum();
        for (Map.Entry<String, Integer> e : results.entrySet()) {
            double pct = total == 0 ? 0 : (e.getValue() * 100.0 / total);
            sb.append(String.format("%-20s %3d  (%.1f%%)\n",
                    e.getKey(), e.getValue(), pct));
        }
        sb.append("---------------------------\n");
        sb.append("ukupno: ").append(total).append("\n");

        Signature sig = Signature.getInstance("SHA256WithRSA", "BC");
        sig.initSign(organizerPrivateKey);
        sig.update(sb.toString().getBytes("UTF-8"));
        byte[] signature = sig.sign();
        String sigHex    = CryptoService.bytesToHex(signature);

        sb.append("---------------------------\n");
        sb.append("potpis: ").append(sigHex, 0, 32).append("...\n");
        sb.append("===========================\n");

        String report     = sb.toString();
        String reportPath = "data/elections/" + election.getId() + "_report.txt";
        Files.writeString(Paths.get(reportPath), report);
        System.out.println("izvještaj sačuvan: " + reportPath);

        return report;
    }

    public ElectionStore getElectionStore() { return electionStore; }
}
