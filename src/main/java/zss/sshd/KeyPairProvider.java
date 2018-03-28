package zss.sshd;

import java.security.KeyPair;
import java.util.LinkedList;
import java.util.List;

public class KeyPairProvider implements org.apache.sshd.common.keyprovider.KeyPairProvider {
    private final List<KeyPair> list = new LinkedList<>();

    public KeyPairProvider(final KeyPair keyPair) {
        list.add(keyPair);
    }

    @Override
    public Iterable<KeyPair> loadKeys() {
        return list;
    }
}
