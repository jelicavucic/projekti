package evoting.auth;

import evoting.ca.CAStore;
import evoting.crypto.CryptoService;
import evoting.model.User;
import evoting.storage.UserStore;

import java.security.cert.X509Certificate;
import java.util.Date;

public class AuthService {

    private final CAStore   caStore;
    private final UserStore userStore;

    public AuthService(CAStore caStore, UserStore userStore) {
        this.caStore   = caStore;
        this.userStore = userStore;
    }

    public User validateCertificate(X509Certificate cert) throws Exception {

        try {
            cert.checkValidity(new Date());
        } catch (Exception e) {
            throw new Exception("sertifikat nije vremenski validan");
        }

        String issuerCN = cert.getIssuerX500Principal().getName();
        java.security.cert.X509Certificate caCert;

        if (issuerCN.contains("Org CA")) {
            caCert = caStore.getOrgCA().getCertificate();
        } else if (issuerCN.contains("Voter CA")) {
            caCert = caStore.getVoterCA().getCertificate();
        } else {
            throw new Exception("nepoznat izdavač sertifikata");
        }

        try {
            cert.verify(caCert.getPublicKey());
        } catch (Exception e) {
            throw new Exception("potpis sertifikata nije validan");
        }

        if (caStore.getCrlManager().isRevoked(cert))
            throw new Exception("sertifikat je povučen");

        String username = extractUsername(cert, issuerCN.contains("Org CA"));
        User   user     = userStore.getUser(username);
        if (user == null)
            throw new Exception("korisnik ne postoji: " + username);

        X509Certificate stored = userStore.loadCertificate(username);
        if (!cert.getSerialNumber().equals(stored.getSerialNumber()))
            throw new Exception("sertifikat ne pripada ovom korisniku");

        return user;
    }

    public User validateCredentials(User user, String username,
                                     String password) throws Exception {
        if (!user.getUsername().equals(username))
            throw new Exception("pogrešno korisničko ime");

        if (!CryptoService.verifyPassword(password, user.getPasswordHash())) {
            user.incrementFailedLogins();
            userStore.updateUserData(user);

            int remaining = 3 - user.getFailedLogins();
            if (user.getFailedLogins() >= 3) {
                user.revoke();
                userStore.updateUserData(user);
                caStore.getCrlManager().revoke(userStore.loadCertificate(username));
                throw new Exception("previše neuspješnih pokušaja — nalog zaključan");
            }
            throw new Exception("pogrešna lozinka (preostalo: " + remaining + ")");
        }

        user.resetFailedLogins();
        userStore.updateUserData(user);
        return user;
    }

    private String extractUsername(X509Certificate cert, boolean isOrganizer) {
        org.bouncycastle.asn1.x500.X500Name name =
                org.bouncycastle.asn1.x500.X500Name.getInstance(
                        cert.getSubjectX500Principal().getEncoded());

        if (isOrganizer) {
            org.bouncycastle.asn1.x500.RDN[] rdns =
                    name.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.SERIALNUMBER);
            if (rdns.length > 0)
                return rdns[0].getFirst().getValue().toString();
        } else {
            org.bouncycastle.asn1.x500.RDN[] rdns =
                    name.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.UID);
            if (rdns.length > 0)
                return rdns[0].getFirst().getValue().toString();
        }
        return cert.getSubjectX500Principal().getName();
    }
}
