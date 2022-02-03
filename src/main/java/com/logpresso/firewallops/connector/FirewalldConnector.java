package com.logpresso.firewallops.connector;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.util.List;

import com.logpresso.firewallops.IoUtils;
import com.logpresso.firewallops.PlatformUtils;

public class FirewalldConnector implements FirewallConnector {

	private static final File configFile = new File("/etc/firewalld/ipsets/logpresso-watch.xml");
	private static final File backupFile = new File("/etc/firewalld/ipsets/logpresso-watch.xml.old");

	public void install() {
		try {
			// create ipset
			if (!configFile.exists()) {
				List<String> output = PlatformUtils.execute("firewall-cmd", "--permanent", "--new-ipset=logpresso-watch",
						"--type=hash:ip");

				if (!"success".equals(output.get(output.size() - 1)))
					throw new IllegalStateException("Cannot create ipset - " + output.get(0));
			}

			PlatformUtils.execute("firewall-cmd", "--permanent", "--zone=drop", "--add-source=ipset:logpresso-watch");

			reloadFirewalld();

			System.out.println("Installed logpresso-watch ipset on firewalld.");
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	public void uninstall() {
		if (!configFile.exists())
			throw new IllegalStateException("logpresso-firewall-ops.xml not found");

		try {
			// remove drop rule
			List<String> output = PlatformUtils.execute("firewall-cmd", "--permanent", "--zone=drop",
					"--remove-source=ipset:logpresso-watch");
			if (!"success".equals(output.get(output.size() - 1)))
				throw new IllegalStateException("Cannot delete drop rule - " + output.get(0));

			// remove ipset
			output = PlatformUtils.execute("firewall-cmd", "--permanent", "--delete-ipset=logpresso-watch");
			if (!"success".equals(output.get(output.size() - 1)))
				throw new IllegalStateException("Cannot delete ipset - " + output.get(0));

			reloadFirewalld();

			System.out.println("Uninstalled logpresso-watch ipset from firewalld.");
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	private void reloadFirewalld() throws IOException {
		List<String> output = PlatformUtils.execute("firewall-cmd", "--reload");
		if (!"success".equals(output.get(output.size() - 1)))
			throw new IllegalStateException("Cannot reload firewalld - " + output.get(0));
	}

	public void deployBlocklist(List<InetAddress> addresses) {
		backupFile.delete();
		configFile.renameTo(backupFile);

		BufferedWriter bw = null;
		try {
			bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(configFile), "utf-8"));
			bw.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
			bw.write("<ipset type=\"hash:ip\">");
			for (InetAddress addr : addresses) {
				bw.write("  <entry>" + addr.getHostAddress() + "</entry>");
			}
			bw.write("</ipset>");

			reloadFirewalld();
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage(), e);
		} finally {
			IoUtils.ensureClose(bw);
		}
	}
}
