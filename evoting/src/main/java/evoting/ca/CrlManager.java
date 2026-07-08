package evoting.ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

public class CrlManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ORG_CRL   = "data/ca/org-ca.crl";
    private static final String VOTER_CRL = "data/ca/voter-ca.crl";

    private final X509Certificate orgCaCert;
    private final PrivateKey      orgCaKey;
    private final X509Certificate voterCaCert;
    private final PrivateKey      voterCaKey;

    private final Set<BigInteger> revokedByOrg   = new HashSet<>();
    private final Set<BigInteger> revokedByVoter = new HashSet<>();

    public CrlManager(X509Certificate orgCaCert,   PrivateKey orgCaKey,
                      X509Certificate voterCaCert, PrivateKey voterCaKey) throws Exception {
        this.orgCaCert   = orgCaCert;
        this.orgCaKey    = orgCaKey;
        this.voterCaCert = voterCaCert;
        this.voterCaKey  = voterCaKey;
        loadFromDisk();
    }

    public void revoke(X509Certificate cert) throws Exception {
        String     issuer = cert.getIssuerX500Principal().getName();
        BigInteger serial = cert.getSerialNumber();

        if (issuer.contains("Org CA")) {
            revokedByOrg.add(serial);
            saveCrl(orgCaCert, orgCaKey, revokedByOrg, ORG_CRL);
        } else {
            revokedByVoter.add(serial);
            saveCrl(voterCaCert, voterCaKey, revokedByVoter, VOTER_CRL);
        }
        System.out.println("sertifikat povučen: " + serial);
    }

    public boolean isRevoked(X509Certificate cert) {
        String     issuer = cert.getIssuerX500Principal().getName();
        BigInteger serial = cert.getSerialNumber();

        if (issuer.contains("Org CA"))
            return revokedByOrg.contains(serial);
        else
            return revokedByVoter.contains(serial);
    }

    private void saveCrl(X509Certificate caCert, PrivateKey caKey,
                         Set<BigInteger> revoked, String path) throws Exception {
        X500Name issuerName = new X500Name(caCert.getSubjectX500Principal().getName());
        Date now        = new Date();
        Date nextUpdate = new Date(now.getTime() + 24L * 60 * 60 * 1000);

        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerName, now);
        builder.setNextUpdate(nextUpdate);
        for (BigInteger serial : revoked)
            builder.addCRLEntry(serial, now, CRLReason.keyCompromise);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(caKey);

        X509CRL crl = new JcaX509CRLConverter()
                .setProvider("BC").getCRL(builder.build(signer));

        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(crl.getEncoded());
        }
    }

    private void loadFromDisk() throws Exception {
        loadCrlFile(ORG_CRL,   revokedByOrg,   orgCaCert.getPublicKey());
        loadCrlFile(VOTER_CRL, revokedByVoter, voterCaCert.getPublicKey());
    }

    private void loadCrlFile(String path, Set<BigInteger> target,
                             PublicKey caPublicKey) throws Exception {
        if (!Files.exists(Paths.get(path))) return;

        byte[] bytes = Files.readAllBytes(Paths.get(path));
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(bytes));

        try {
            crl.verify(caPublicKey, "BC");
        } catch (Exception e) {
            throw new Exception("CRL potpis nije validan: " + path + " — " + e.getMessage());
        }

        if (crl.getRevokedCertificates() != null)
            for (var entry : crl.getRevokedCertificates())
                target.add(entry.getSerialNumber());
    }
}