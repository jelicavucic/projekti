package evoting.ca;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;

public class CAStore {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String CA_DIR    = "data/ca/";
    private static final String ROOT_P12  = CA_DIR + "root-ca.p12";
    private static final String ORG_P12   = CA_DIR + "org-ca.p12";
    private static final String VOTER_P12 = CA_DIR + "voter-ca.p12";

    private char[] caPass;

    private RootCA     rootCA;
    private OrgCA      orgCA;
    private VoterCA    voterCA;
    private CrlManager crlManager;

    public void initializeOrLoad() throws Exception {
        Files.createDirectories(Paths.get(CA_DIR));

        caPass = readPassword("CA lozinka: ");

        if (caFilesExist()) {
            System.out.println("učitavanje ca...");
            loadAll();
        } else {
            System.out.println("ca nije pronađen, kreiram...");
            generateAll();
            saveAll();
        }

        crlManager = new CrlManager(
                orgCA.getCertificate(),   orgCA.getPrivateKey(),
                voterCA.getCertificate(), voterCA.getPrivateKey());
    }

    private char[] readPassword(String prompt) {
        System.out.print(prompt);
        if (System.console() != null) {
            return System.console().readPassword();
        } else {
            return new Scanner(System.in).nextLine().toCharArray();
        }
    }

    private boolean caFilesExist() {
        return Files.exists(Paths.get(ROOT_P12))
                && Files.exists(Paths.get(ORG_P12))
                && Files.exists(Paths.get(VOTER_P12));
    }

    private void generateAll() throws Exception {
        rootCA  = RootCA.generate();
        orgCA   = OrgCA.generate(rootCA);
        voterCA = VoterCA.generate(rootCA);
    }

    private void saveAll() throws Exception {
        System.out.println("čuvanje na disk...");
        saveKeyStore(ROOT_P12,  "root-ca",  rootCA.getPrivateKey(),  rootCA.getCertificate());
        saveKeyStore(ORG_P12,   "org-ca",   orgCA.getPrivateKey(),   orgCA.getCertificate());
        saveKeyStore(VOTER_P12, "voter-ca", voterCA.getPrivateKey(), voterCA.getCertificate());
        System.out.println("gotovo.");
    }

    private void saveKeyStore(String path, String alias,
                              PrivateKey privateKey,
                              X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry(alias, privateKey, caPass,
                new java.security.cert.Certificate[]{ cert });
        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, caPass);
        }
    }

    private void loadAll() throws Exception {
        KeyStore rootKS  = loadKeyStore(ROOT_P12);
        KeyStore orgKS   = loadKeyStore(ORG_P12);
        KeyStore voterKS = loadKeyStore(VOTER_P12);

        rootCA  = RootCA.fromStore(rootKS,   "root-ca",  caPass);
        orgCA   = OrgCA.fromStore(orgKS,     "org-ca",   caPass);
        voterCA = VoterCA.fromStore(voterKS, "voter-ca", caPass);

        System.out.println("root-ca  [ok]");
        System.out.println("org-ca   [ok]");
        System.out.println("voter-ca [ok]");
    }

    private KeyStore loadKeyStore(String path) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, caPass);
        }
        return ks;
    }

    public RootCA     getRootCA()     { return rootCA; }
    public OrgCA      getOrgCA()      { return orgCA; }
    public VoterCA    getVoterCA()    { return voterCA; }
    public CrlManager getCrlManager() { return crlManager; }
}