package evoting.storage;

import evoting.model.User;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

public class UserStore {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String USERS_DIR = "data/users/";

    private final Map<String, User> users = new HashMap<>();

    public UserStore() throws Exception {
        Files.createDirectories(Paths.get(USERS_DIR));
        loadAllUsers();
    }

    public void registerUser(User user, X509Certificate cert,
                              PrivateKey privateKey, char[] password) throws Exception {
        if (users.containsKey(user.getUsername()))
            throw new IllegalArgumentException("korisničko ime već postoji");

        saveCertificate(user.getUsername(), cert);
        savePrivateKey(user.getUsername(), privateKey, cert, password);
        saveUserData(user);
        users.put(user.getUsername(), user);

        System.out.println("registracija uspješna: " + user.getUsername());
    }

    private void saveCertificate(String username, X509Certificate cert) throws Exception {
        String path = USERS_DIR + username + ".crt";
        try (PrintWriter pw = new PrintWriter(path)) {
            pw.println("-----BEGIN CERTIFICATE-----");
            pw.println(Base64.getMimeEncoder(64, new byte[]{'\n'})
                    .encodeToString(cert.getEncoded()));
            pw.println("-----END CERTIFICATE-----");
        }
    }

    public X509Certificate loadCertificate(String username) throws Exception {
        String path = USERS_DIR + username + ".crt";
        if (!Files.exists(Paths.get(path)))
            throw new Exception("sertifikat nije pronađen za: " + username);

        byte[] bytes = Files.readAllBytes(Paths.get(path));
        String pem   = new String(bytes)
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(pem);

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(decoded));
    }

    private void savePrivateKey(String username, PrivateKey privateKey,
                                 X509Certificate cert, char[] password) throws Exception {
        String   path = USERS_DIR + username + ".p12";
        KeyStore ks   = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry(username, privateKey, password,
                new java.security.cert.Certificate[]{ cert });
        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password);
        }
    }

    public PrivateKey loadPrivateKey(String username, char[] password) throws Exception {
        String   path = USERS_DIR + username + ".p12";
        KeyStore ks   = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password);
        }
        return (PrivateKey) ks.getKey(username, password);
    }

    private void saveUserData(User user) throws Exception {
        String     path  = USERS_DIR + user.getUsername() + ".properties";
        Properties props = new Properties();

        props.setProperty("username",     user.getUsername());
        props.setProperty("passwordHash", user.getPasswordHash());
        props.setProperty("role",         user.getRole().name());
        props.setProperty("failedLogins", String.valueOf(user.getFailedLogins()));
        props.setProperty("revoked",      String.valueOf(user.isRevoked()));

        if (user.isOrganizer()) {
            props.setProperty("orgName", user.getOrgName());
            props.setProperty("orgId",   user.getOrgId());
        } else {
            props.setProperty("firstName", user.getFirstName());
            props.setProperty("lastName",  user.getLastName());
        }

        try (FileOutputStream fos = new FileOutputStream(path)) {
            props.store(fos, null);
        }
    }

    public void updateUserData(User user) throws Exception {
        saveUserData(user);
    }

    private void loadAllUsers() throws Exception {
        File   dir      = new File(USERS_DIR);
        File[] propFiles = dir.listFiles((d, name) -> name.endsWith(".properties"));
        if (propFiles == null) return;

        for (File f : propFiles) {
            User user = loadUserFromFile(f);
            users.put(user.getUsername(), user);
        }
    }

    private User loadUserFromFile(File file) throws Exception {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(file)) {
            props.load(fis);
        }

        String  username     = props.getProperty("username");
        String  passwordHash = props.getProperty("passwordHash");
        String  role         = props.getProperty("role");
        int     failedLogins = Integer.parseInt(props.getProperty("failedLogins", "0"));
        boolean revoked      = Boolean.parseBoolean(props.getProperty("revoked", "false"));

        User user;
        if ("ORGANIZER".equals(role)) {
            user = new User(username, passwordHash,
                    props.getProperty("orgName"), props.getProperty("orgId"));
        } else {
            user = new User(username, passwordHash,
                    props.getProperty("firstName"), props.getProperty("lastName"), true);
        }

        for (int i = 0; i < failedLogins; i++) user.incrementFailedLogins();
        if (revoked) user.revoke();

        return user;
    }

    public User    getUser(String username) { return users.get(username); }
    public boolean exists(String username)  { return users.containsKey(username); }
}
