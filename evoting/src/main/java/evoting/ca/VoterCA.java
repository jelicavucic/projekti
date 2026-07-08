package evoting.ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class VoterCA {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    private VoterCA(KeyPair keyPair, X509Certificate certificate) {
        this.keyPair     = keyPair;
        this.certificate = certificate;
    }

    public static VoterCA generate(RootCA rootCA) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name subjectName = new X500Name("CN=EVoting Voter CA,O=ETF Banja Luka,C=BA");
        X509Certificate cert = rootCA.signSubCA(keyPair.getPublic(), subjectName);

        System.out.println("[voter-ca] potpisan");
        return new VoterCA(keyPair, cert);
    }

    public static VoterCA fromStore(KeyStore ks, String alias, char[] password) throws Exception {
        PrivateKey      privateKey = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert       = (X509Certificate) ks.getCertificate(alias);
        KeyPair         keyPair    = new KeyPair(cert.getPublicKey(), privateKey);
        return new VoterCA(keyPair, cert);
    }

    public X509Certificate issueVoterCert(PublicKey voterPublicKey,
                                           String firstName,
                                           String lastName,
                                           String username) throws Exception {
        X500Name issuerName  = new X500Name(certificate.getSubjectX500Principal().getName());
        X500Name subjectName = new X500Name(
                "CN=" + firstName + " " + lastName + ",UID=" + username
                + ",O=ETF Banja Luka,C=BA");

        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore    = new Date();
        Date notAfter     = new Date(notBefore.getTime() + 2L * 365 * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, serial, notBefore, notAfter, subjectName, voterPublicKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));
    }

    public X509Certificate getCertificate() { return certificate; }
    public PrivateKey       getPrivateKey()  { return keyPair.getPrivate(); }
    public PublicKey        getPublicKey()   { return keyPair.getPublic(); }
}
