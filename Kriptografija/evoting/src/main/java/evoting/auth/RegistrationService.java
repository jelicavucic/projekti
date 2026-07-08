package evoting.auth;

import evoting.ca.OrgCA;
import evoting.ca.VoterCA;
import evoting.crypto.CryptoService;
import evoting.model.User;
import evoting.storage.UserStore;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class RegistrationService {

    private final OrgCA     orgCA;
    private final VoterCA   voterCA;
    private final UserStore userStore;

    public RegistrationService(OrgCA orgCA, VoterCA voterCA, UserStore userStore) {
        this.orgCA     = orgCA;
        this.voterCA   = voterCA;
        this.userStore = userStore;
    }

    public void registerOrganizer(String username, String password,
                                   String orgName, String orgId) throws Exception {
        if (userStore.exists(username))
            throw new IllegalArgumentException("korisničko ime zauzeto");

        String  passwordHash = CryptoService.hashPassword(password);
        User    user         = new User(username, passwordHash, orgName, orgId);
        KeyPair keyPair      = CryptoService.generateUserKeyPair();

        X509Certificate cert = orgCA.issueOrgCert(keyPair.getPublic(), orgName, orgId, username);
        userStore.registerUser(user, cert, keyPair.getPrivate(), password.toCharArray());
    }

    public void registerVoter(String username, String password,
                               String firstName, String lastName) throws Exception {
        if (userStore.exists(username))
            throw new IllegalArgumentException("korisničko ime zauzeto");

        String  passwordHash = CryptoService.hashPassword(password);
        User    user         = new User(username, passwordHash, firstName, lastName, true);
        KeyPair keyPair      = CryptoService.generateUserKeyPair();

        X509Certificate cert = voterCA.issueVoterCert(
                keyPair.getPublic(), firstName, lastName, username);
        userStore.registerUser(user, cert, keyPair.getPrivate(), password.toCharArray());
    }
}
