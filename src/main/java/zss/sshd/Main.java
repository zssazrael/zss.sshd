package zss.sshd;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.LinkedList;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) throws Exception {
        final BouncyCastleProvider provider = new BouncyCastleProvider();
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGenerator.initialize(1024);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPasswordAuthenticator(new PasswordAuthenticator());
        sshd.setKeyPairProvider(new KeyPairProvider(keyPair));
        sshd.setSubsystemFactories(new LinkedList<>());
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        sshd.setPort(22);
        sshd.start();
        while (!sshd.isClosed()) {
            Thread.sleep(1000 * 60 * 4);
        }
    }
}
