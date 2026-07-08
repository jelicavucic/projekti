package evoting.storage;

import evoting.crypto.CryptoService;
import evoting.model.Election;
import evoting.model.Vote;

import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ElectionStore {

    private static final String ELECTIONS_DIR = "data/elections/";
    private static final String VOTES_DIR     = "data/votes/";
    private static final String HMAC_KEY_PATH = "data/ca/hmac.key";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private final Map<String, Election> elections = new HashMap<>();

    private byte[] hmacKey;

    public ElectionStore() throws Exception {
        Files.createDirectories(Paths.get(ELECTIONS_DIR));
        Files.createDirectories(Paths.get(VOTES_DIR));
        initializeHmacKey();
        loadAllElections();
    }

    private void initializeHmacKey() throws Exception {
        Path path = Paths.get(HMAC_KEY_PATH);
        if (Files.exists(path)) {
            hmacKey = Files.readAllBytes(path);
        } else {
            hmacKey = new byte[32]; // 256 bita
            new SecureRandom().nextBytes(hmacKey);
            Files.createDirectories(path.getParent());
            Files.write(path, hmacKey);
            System.out.println("generisan novi HMAC ključ.");
        }
    }

    public void saveElection(Election election) throws Exception {
        String     path  = ELECTIONS_DIR + election.getId() + ".properties";
        Properties props = new Properties();

        props.setProperty("id",          election.getId());
        props.setProperty("title",       election.getTitle());
        props.setProperty("description", election.getDescription());
        props.setProperty("options",     String.join("|", election.getOptions()));
        props.setProperty("startTime",   election.getStartTime().format(FMT));
        props.setProperty("endTime",     election.getEndTime().format(FMT));
        props.setProperty("organizer",   election.getOrganizerUsername());
        props.setProperty("status",      election.getStatus().name());

        String hmacData = election.getId() + election.getTitle() +
                election.getOrganizerUsername() +
                election.getStartTime().format(FMT) +
                election.getEndTime().format(FMT);
        props.setProperty("hmac", CryptoService.computeHmac(hmacData, hmacKey));

        try (FileOutputStream fos = new FileOutputStream(path)) {
            props.store(fos, null);
        }
        elections.put(election.getId(), election);
    }

    private void loadAllElections() throws Exception {
        File   dir   = new File(ELECTIONS_DIR);
        File[] files = dir.listFiles((d, n) -> n.endsWith(".properties"));
        if (files == null) return;

        for (File f : files) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(f)) {
                props.load(fis);
            }

            String hmacData = props.getProperty("id") +
                    props.getProperty("title") +
                    props.getProperty("organizer") +
                    props.getProperty("startTime") +
                    props.getProperty("endTime");
            String stored   = props.getProperty("hmac", "");
            String computed = CryptoService.computeHmac(hmacData, hmacKey);

            if (!stored.equals(computed)) {
                System.out.println("upozorenje: integritet narušen — " + f.getName());
                continue;
            }

            List<String> options = Arrays.asList(
                    props.getProperty("options").split("\\|"));

            Election election = new Election(
                    props.getProperty("id"),
                    props.getProperty("title"),
                    props.getProperty("description"),
                    options,
                    LocalDateTime.parse(props.getProperty("startTime"), FMT),
                    LocalDateTime.parse(props.getProperty("endTime"),   FMT),
                    props.getProperty("organizer"));
            election.setStatus(Election.Status.valueOf(props.getProperty("status")));
            elections.put(election.getId(), election);
        }
    }


    public void saveVote(Vote vote) throws Exception {
        String dir = VOTES_DIR + vote.getElectionId() + "/";
        Files.createDirectories(Paths.get(dir));

        Properties props = new Properties();
        props.setProperty("voteId",          vote.getId());
        props.setProperty("electionId",      vote.getElectionId());
        props.setProperty("voterUsername",   vote.getVoterUsername());
        props.setProperty("encryptedVote",   Base64.getEncoder().encodeToString(vote.getEncryptedVote()));
        props.setProperty("encryptedAesKey", Base64.getEncoder().encodeToString(vote.getEncryptedAesKey()));
        props.setProperty("iv",              Base64.getEncoder().encodeToString(vote.getIv()));
        props.setProperty("signature",       Base64.getEncoder().encodeToString(vote.getSignature()));
        props.setProperty("voteHash",        vote.getVoteHash());

        String hmacData = vote.getId() + vote.getElectionId() + vote.getVoterUsername() + vote.getVoteHash();
        props.setProperty("hmac", CryptoService.computeHmac(hmacData, hmacKey));

        try (FileOutputStream fos = new FileOutputStream(dir + vote.getId() + ".properties")) {
            props.store(fos, null);
        }
    }

    public List<Vote> loadAllVotes(String electionId) throws Exception {
        String     dir    = VOTES_DIR + electionId + "/";
        List<Vote> votes  = new ArrayList<>();
        File       folder = new File(dir);
        if (!folder.exists()) return votes;

        for (File f : Objects.requireNonNull(folder.listFiles())) {
            if (!f.getName().endsWith(".properties")) continue;
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(f)) {
                props.load(fis);
            }

            String hmacData = props.getProperty("voteId") +
                    props.getProperty("electionId") +
                    props.getProperty("voterUsername") +
                    props.getProperty("voteHash");
            String stored   = props.getProperty("hmac", "");
            String computed = CryptoService.computeHmac(hmacData, hmacKey);

            if (!stored.equals(computed)) {
                System.out.println("UPOZORENJE: Integritet glasa narušen! Preskačem fajl: " + f.getName());
                continue;
            }

            votes.add(new Vote(
                    props.getProperty("voteId"),
                    props.getProperty("electionId"),
                    props.getProperty("voterUsername"),
                    Base64.getDecoder().decode(props.getProperty("encryptedVote")),
                    Base64.getDecoder().decode(props.getProperty("encryptedAesKey")),
                    Base64.getDecoder().decode(props.getProperty("iv")),
                    Base64.getDecoder().decode(props.getProperty("signature")),
                    props.getProperty("voteHash")));
        }
        return votes;
    }

    public boolean hasVoted(String electionId, String voterUsername) {
        String dir    = VOTES_DIR + electionId + "/";
        File   folder = new File(dir);
        if (!folder.exists()) return false;
        File[] files = folder.listFiles();
        if (files == null) return false;
        for (File f : files)
            if (f.getName().startsWith(voterUsername + "_")) return true;
        return false;
    }

    public Election              getElection(String id)               { return elections.get(id); }
    public Map<String, Election> getElections()                       { return elections; }

    public List<Election> getActiveElections() {
        List<Election> result = new ArrayList<>();
        for (Election e : elections.values())
            if (e.computeStatus() == Election.Status.ACTIVE) result.add(e);
        return result;
    }

    public List<Election> getElectionsByOrganizer(String username) {
        List<Election> result = new ArrayList<>();
        for (Election e : elections.values())
            if (e.getOrganizerUsername().equals(username)) result.add(e);
        return result;
    }
}