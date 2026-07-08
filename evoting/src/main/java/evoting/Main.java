package evoting;

import evoting.auth.AuthService;
import evoting.auth.RegistrationService;
import evoting.ca.CAStore;
import evoting.model.Election;
import evoting.model.User;
import evoting.storage.ElectionStore;
import evoting.storage.UserStore;
import evoting.voting.VotingService;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Main {

    private static final Scanner scanner = new Scanner(System.in);
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private static CAStore              caStore;
    private static UserStore            userStore;
    private static ElectionStore        electionStore;
    private static RegistrationService  registrationService;
    private static AuthService          authService;
    private static VotingService        votingService;

    public static void main(String[] args) {
        System.out.println("e-voting / etf bl\n");

        try {
            caStore = new CAStore();
            caStore.initializeOrLoad();

            userStore     = new UserStore();
            electionStore = new ElectionStore();

            registrationService = new RegistrationService(
                    caStore.getOrgCA(), caStore.getVoterCA(), userStore);
            authService   = new AuthService(caStore, userStore);
            votingService = new VotingService(electionStore, userStore);

        } catch (Exception e) {
            System.err.println("greška pri pokretanju: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        mainMenu();
    }

    private static void mainMenu() {
        while (true) {
            System.out.println("\n1. registracija");
            System.out.println("2. prijava");
            System.out.println("0. izlaz");
            System.out.print("> ");

            switch (scanner.nextLine().trim()) {
                case "1" -> registrationMenu();
                case "2" -> loginMenu();
                case "0" -> { System.out.println("doviđenja."); return; }
                default  -> System.out.println("?");
            }
        }
    }

    private static void registrationMenu() {
        System.out.println("\n1. organizator");
        System.out.println("2. glasač");
        System.out.print("> ");

        switch (scanner.nextLine().trim()) {
            case "1" -> registerOrganizer();
            case "2" -> registerVoter();
            default  -> System.out.println("?");
        }
    }

    private static void registerOrganizer() {
        try {
            System.out.print("naziv organizacije: ");
            String orgName = scanner.nextLine().trim();
            System.out.print("identifikacioni broj: ");
            String orgId = scanner.nextLine().trim();
            System.out.print("korisničko ime: ");
            String username = scanner.nextLine().trim();
            System.out.print("lozinka: ");
            String password = scanner.nextLine().trim();

            registrationService.registerOrganizer(username, password, orgName, orgId);
        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void registerVoter() {
        try {
            System.out.print("ime: ");
            String firstName = scanner.nextLine().trim();
            System.out.print("prezime: ");
            String lastName = scanner.nextLine().trim();
            System.out.print("korisničko ime: ");
            String username = scanner.nextLine().trim();
            System.out.print("lozinka: ");
            String password = scanner.nextLine().trim();

            registrationService.registerVoter(username, password, firstName, lastName);
        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void loginMenu() {
        try {
            System.out.print("putanja do sertifikata (.crt): ");
            String certPath = scanner.nextLine().trim();

            byte[] bytes = Files.readAllBytes(Paths.get(certPath));
            String pem = new String(bytes)
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));

            User user = authService.validateCertificate(cert);

            System.out.print("korisničko ime: ");
            String username = scanner.nextLine().trim();
            System.out.print("lozinka: ");
            String password = scanner.nextLine().trim();

            user = authService.validateCredentials(user, username, password);
            System.out.println("prijava uspješna.\n");

            if (user.isOrganizer()) organizerMenu(user);
            else                    voterMenu(user);

        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void organizerMenu(User user) {
        System.out.println("dobrodošli, " + user.getOrgName());
        while (true) {
            System.out.println("\n1. kreiraj glasanje");
            System.out.println("2. moja glasanja");
            System.out.println("3. broji glasove");
            System.out.println("0. odjava");
            System.out.print("> ");

            switch (scanner.nextLine().trim()) {
                case "1" -> createElection(user);
                case "2" -> listOrganizerElections(user);
                case "3" -> countVotes(user);
                case "0" -> { return; }
                default  -> System.out.println("?");
            }
        }
    }

    private static void createElection(User organizer) {
        try {
            System.out.print("naslov: ");
            String title = scanner.nextLine().trim();
            System.out.print("opis: ");
            String desc = scanner.nextLine().trim();
            System.out.print("početak (yyyy-MM-dd HH:mm): ");
            LocalDateTime start = LocalDateTime.parse(scanner.nextLine().trim(), FMT);
            System.out.print("kraj    (yyyy-MM-dd HH:mm): ");
            LocalDateTime end = LocalDateTime.parse(scanner.nextLine().trim(), FMT);

            System.out.print("broj opcija (2-5): ");
            int n = Integer.parseInt(scanner.nextLine().trim());
            List<String> options = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                System.out.print("opcija " + (i + 1) + ": ");
                options.add(scanner.nextLine().trim());
            }

            votingService.createElection(organizer, title, desc, options, start, end);
        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void listOrganizerElections(User organizer) {
        List<Election> list = electionStore.getElectionsByOrganizer(organizer.getUsername());
        if (list.isEmpty()) { System.out.println("nema glasanja."); return; }
        for (Election e : list)
            System.out.printf("%-30s %-14s [%s — %s]%n",
                    e.getId(), e.computeStatus(),
                    e.getStartTime().format(FMT), e.getEndTime().format(FMT));
    }

    private static void countVotes(User organizer) {
        try {
            listOrganizerElections(organizer);
            System.out.print("id glasanja: ");
            String id = scanner.nextLine().trim();

            Election election = electionStore.getElection(id);
            if (election == null) { System.out.println("ne postoji."); return; }

            System.out.print("lozinka (za privatni ključ): ");
            String password = scanner.nextLine().trim();
            PrivateKey key  = userStore.loadPrivateKey(
                    organizer.getUsername(), password.toCharArray());

            Map<String, Integer> results = votingService.countVotes(election, key);
            String report = votingService.generateReport(election, results, key);
            System.out.println(report);
        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void voterMenu(User user) {

        System.out.println("dobrodošli, " + user.getFirstName());
        Map<String, String> myVoteHashes = new HashMap<>();

        while (true) {
            System.out.println("\n1. glasaj");
            System.out.println("2. verifikuj moj glas");
            System.out.println("0. odjava");
            System.out.print("> ");

            switch (scanner.nextLine().trim()) {
                case "1" -> castVote(user, myVoteHashes);
                case "2" -> verifyVote(user, myVoteHashes);
                case "0" -> { return; }
                default  -> System.out.println("?");
            }
        }
    }

    private static void castVote(User voter, Map<String, String> myVoteHashes) {
        try {
            List<Election> active = electionStore.getActiveElections();
            if (active.isEmpty()) { System.out.println("nema aktivnih glasanja."); return; }

            for (int i = 0; i < active.size(); i++)
                System.out.println((i + 1) + ". " + active.get(i).getTitle());

            System.out.print("odaberi glasanje: ");
            int      idx      = Integer.parseInt(scanner.nextLine().trim()) - 1;
            Election election = active.get(idx);

            System.out.println("\n" + election.getTitle());
            System.out.println(election.getDescription());
            List<String> options = election.getOptions();
            for (int i = 0; i < options.size(); i++)
                System.out.println((i + 1) + ". " + options.get(i));

            System.out.print("tvoj glas: ");
            int optIdx = Integer.parseInt(scanner.nextLine().trim()) - 1;

            System.out.print("lozinka (za potpis): ");
            String     password = scanner.nextLine().trim();
            PrivateKey key      = userStore.loadPrivateKey(
                    voter.getUsername(), password.toCharArray());

            String hash = votingService.castVote(voter, election, optIdx, key);
            myVoteHashes.put(election.getId(), hash);
            System.out.println("hash glasa: " + hash);

        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }

    private static void verifyVote(User voter, Map<String, String> myVoteHashes) {
        try {
            if (myVoteHashes.isEmpty()) {
                System.out.println("nema glasova u ovoj sesiji.");
                return;
            }

            myVoteHashes.forEach((elId, hash) ->
                    System.out.println(elId + " → " + hash));

            System.out.print("id glasanja: ");
            String elId = scanner.nextLine().trim();
            String hash = myVoteHashes.get(elId);
            if (hash == null) { System.out.println("ne postoji."); return; }

            PublicKey pubKey = userStore.loadCertificate(voter.getUsername()).getPublicKey();
            boolean   ok     = votingService.verifyVote(elId, voter.getUsername(), hash, pubKey);
            System.out.println(ok ? "glas je ispravno zabilježen." : "verifikacija neuspješna!");

        } catch (Exception e) {
            System.out.println("greška: " + e.getMessage());
        }
    }
}