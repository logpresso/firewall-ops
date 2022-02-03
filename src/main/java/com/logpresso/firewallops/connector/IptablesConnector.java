package com.logpresso.firewallops.connector;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import com.logpresso.firewallops.IoUtils;
import com.logpresso.firewallops.PlatformUtils;

public class IptablesConnector implements FirewallConnector {

	@Override
	public void install() {
		try {
			PlatformUtils.execute("ipset", "-N", "logpresso-watch", "iphash");
			PlatformUtils.execute("iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "logpresso-watch", "src", "-j",
					"DROP");
			System.out.println("Installed logpresso-watch ipset and drop rule to iptables.");
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	public void uninstall() {
		try {
			PlatformUtils.execute("iptables", "-D", "INPUT", "1", "-m", "set", "--match-set", "logpresso-watch", "src");
			PlatformUtils.execute("ipset", "destroy", "logpresso-watch");

			System.out.println("Uninstalled iptables drop rule and logpresso-watch ipset.");
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	public void deployBlocklist(List<InetAddress> addresses) {

		List<String> output = new ArrayList<String>();
		Process p = null;
		BufferedReader br = null;
		BufferedWriter bw = null;
		try {
			PlatformUtils.execute("ipset", "flush", "logpresso-watch");

			// write to stdin of ipset restore command
			String[] commands = new String[] { "ipset", "restore", "-!" };

			commands[0] = PlatformUtils.resolvePath(commands[0]);
			ProcessBuilder pb = new ProcessBuilder(commands);
			pb.redirectErrorStream(true);
			p = pb.start();

			bw = new BufferedWriter(new OutputStreamWriter(p.getOutputStream()));
			bw.write("create logpresso-watch hash:ip family inet hashsize 1024 maxelem 65536\n");
			for (InetAddress addr : addresses)
				bw.write("add logpresso-watch " + addr.getHostAddress() + "\n");

			bw.close();

			br = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				output.add(line);
			}

		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		} finally {
			IoUtils.ensureClose(bw);
			IoUtils.ensureClose(br);

			if (p != null) {
				try {
					p.waitFor();
				} catch (Throwable t) {
				}
			}
		}
	}
}
