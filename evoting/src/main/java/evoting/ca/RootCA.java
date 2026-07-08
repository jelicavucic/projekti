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

public class RootCA {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    private RootCA(KeyPair keyPair, X509Certificate certificate) {
        this.keyPair     = keyPair;
        this.certificate = certificate;
    }

    public static RootCA generate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name subject  = new X500Name("CN=EVoting Root CA,O=ETF Banja Luka,C=BA");
        BigInteger serial = BigInteger.valueOf(1L);
        Date notBefore    = new Date();
        Date notAfter     = new Date(notBefore.getTime() + 10L * 365 * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keyPair.getPrivate());

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));

        System.out.println("[root-ca] generisan");
        return new RootCA(keyPair, cert);
    }

    public static RootCA fromStore(java.security.KeyStore ks,
                                   String alias, char[] password) throws Exception {
        PrivateKey     privateKey = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert      = (X509Certificate) ks.getCertificate(alias);
        KeyPair        keyPair    = new KeyPair(cert.getPublicKey(), privateKey);
        return new RootCA(keyPair, cert);
    }

    public X509Certificate signSubCA(PublicKey subCaPublicKey,
                                      X500Name subCaName) throws Exception {
        BigInteger serial   = new BigInteger(64, new SecureRandom());
        Date notBefore      = new Date();
        Date notAfter       = new Date(notBefore.getTime() + 5L * 365 * 24 * 60 * 60 * 1000);
        X500Name issuerName = new X500Name(certificate.getSubjectX500Principal().getName());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, serial, notBefore, notAfter, subCaName, subCaPublicKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));
    }

    public X509Certificate getCertificate() { return certificate; }
    public PrivateKey       getPrivateKey()  { return keyPair.getPrivate(); }
    public PublicKey        getPublicKey()   { return keyPair.getPublic(); }
}
