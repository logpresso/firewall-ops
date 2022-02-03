package com.logpresso.firewallops.connector;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

public interface FirewallConnector {

	void install() throws IOException;

	void uninstall() throws IOException;

	void deployBlocklist(List<InetAddress> addresses) throws IOException;
}
