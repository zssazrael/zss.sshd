package zss.sshd;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.server.auth.password.StaticPasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordAuthenticator extends StaticPasswordAuthenticator {
    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordAuthenticator.class);

    private final Map<String, Integer> hostMap = new TreeMap<>();

    public PasswordAuthenticator() {
        super(false);
    }

    @Override
    protected synchronized void handleRejection(String username, String password, ServerSession session) {
        final SocketAddress clientAddress = session.getClientAddress();
        if (clientAddress instanceof InetSocketAddress) {
            final InetAddress address = ((InetSocketAddress) clientAddress).getAddress();
            final String host = address.getHostAddress();
            Integer count = hostMap.get(host);
            if (count == null) {
                count = Integer.valueOf(0);
            }
            count = Integer.valueOf(count.intValue() + 1);
            hostMap.put(host, count);
            if (count >= 8) {
                if (address instanceof Inet4Address) {
                    dropIP4(host);
                } else if (address instanceof Inet6Address) {
                    dropIP6(host);
                }
                hostMap.remove(host);
            }
        }
        try {
            session.close();
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void dropIP6(String host) {
        final List<String> command = new LinkedList<>();
        command.add("/usr/sbin/ip6tables");
        command.add("-D");
        command.add("INPUT");
        command.add("-s");
        command.add(host);
        command.add("-j");
        command.add("DROP");
        final ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.redirectErrorStream(true);
        try {
            final Process process = builder.start();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                LOGGER.error(e.getMessage(), e);
            } finally {
                process.destroy();
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
        command.clear();
        command.add("/usr/sbin/ip6tables");
        command.add("-I");
        command.add("INPUT");
        command.add("-s");
        command.add(host);
        command.add("-j");
        command.add("DROP");
        try {
            final Process process = builder.start();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                LOGGER.error(e.getMessage(), e);
            } finally {
                process.destroy();
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void dropIP4(String host) {
        final List<String> command = new LinkedList<>();
        command.add("/usr/sbin/iptables");
        command.add("-D");
        command.add("INPUT");
        command.add("-s");
        command.add(host);
        command.add("-j");
        command.add("DROP");
        final ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.redirectErrorStream(true);
        try {
            final Process process = builder.start();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                LOGGER.error(e.getMessage(), e);
            } finally {
                process.destroy();
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
        command.clear();
        command.add("/usr/sbin/iptables");
        command.add("-I");
        command.add("INPUT");
        command.add("-s");
        command.add(host);
        command.add("-j");
        command.add("DROP");
        try {
            final Process process = builder.start();
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                LOGGER.error(e.getMessage(), e);
            } finally {
                process.destroy();
            }
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
