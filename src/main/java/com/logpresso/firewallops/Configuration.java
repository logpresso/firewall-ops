package com.logpresso.firewallops;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import com.logpresso.firewallops.connector.FirewallConnector;
import com.logpresso.firewallops.connector.FirewalldConnector;
import com.logpresso.firewallops.connector.IptablesConnector;

public class Configuration {
	private UUID apiKey;
	private boolean debug;
	private Backend backend;
	private Set<String> allowlist = new HashSet<String>();

	public static void install(UUID apiKey, InetSocketAddress proxyAddr) {
		Backend backend = installFirewallConnector();
		installConfigFile(backend, apiKey, proxyAddr);
		installSystemdFile();
	}

	public static Configuration load() throws IOException {
		Configuration c = new Configuration();
		Pattern regex = Pattern.compile("\\s+");
		File f = new File(IoUtils.getJarDir(), "logpresso-firewall-ops.conf");
		BufferedReader br = null;

		boolean allowlistSection = false;
		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "utf-8"));
			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();

				if (line.isEmpty() || line.startsWith("#"))
					continue;

				String[] tokens = regex.split(line);
				String descriptor = tokens[0];

				if (descriptor.equals("backend")) {
					String value = getValue(tokens, "Specify backend value");
					try {
						c.backend = Backend.valueOf(value.toUpperCase());
					} catch (IllegalArgumentException e) {
						throw new IllegalArgumentException("Invalid backend type - " + value);
					}
				} else if (descriptor.equals("api-key")) {
					String value = getValue(tokens, "Specify api-key value");
					try {
						c.apiKey = UUID.fromString(value);
					} catch (IllegalArgumentException e) {
						throw new IllegalArgumentException("Invalid api-key format - " + value);
					}
				} else if (descriptor.equals("http-proxy")) {
					try {
						String s = getValue(tokens, "Specify http-proxy value (ip:port format)");
						int p = s.indexOf(':');
						if (p < 0)
							throw new IllegalStateException("Missing http-proxy port - " + s);

						InetAddress host = InetAddress.getByName(s.substring(0, p));
						int port = Integer.parseInt(s.substring(p + 1));
						if (port < 0 || port > 65535)
							throw new IllegalStateException("Invalid http-proxy port number range - " + tokens[1]);

						System.setProperty("https.proxyHost", host.getHostAddress());
						System.setProperty("https.proxyPort", Integer.toString(port));

					} catch (NumberFormatException e) {
						throw new IllegalStateException("Invalid http-proxy port number - " + tokens[1]);
					}
				} else if (descriptor.equals("loglevel")) {
					c.debug = "debug".equals(getValue(tokens, "loglevel value is missing"));
				} else if (descriptor.equals("[allowlist]")) {
					allowlistSection = true;
				} else {
					if (allowlistSection) {
						c.allowlist.add(tokens[0]);
					}
				}
			}

			return c;
		} finally {
			if (br != null)
				br.close();
		}
	}

	private static String getValue(String[] tokens, String error) {
		if (tokens.length < 2)
			throw new IllegalStateException("port number is missing");

		return tokens[1];
	}

	private static Backend installFirewallConnector() {
		// check if firewalld is running
		if (isFirewalldRunning()) {
			new FirewalldConnector().install();
			return Backend.FIREWALLD;
		} else {
			new IptablesConnector().install();
			return Backend.IPTABLES;
		}
	}

	private static boolean isFirewalldRunning() {
		try {
			List<String> output = PlatformUtils.execute("firewalld-cmd", "--state");
			return "running".equals(output.get(0));
		} catch (IOException e) {
			return false;
		}
	}

	private static void installConfigFile(Backend backend, UUID apiKey, InetSocketAddress proxyAddr) {
		File dir = IoUtils.getJarDir();
		File configFile = new File(dir, "logpresso-firewall-ops.conf");
		configFile.getParentFile().mkdirs();
		if (configFile.exists())
			throw new IllegalStateException("Cannot write file to " + configFile.getAbsolutePath());

		BufferedWriter bw = null;
		try {
			bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(configFile), "utf-8"));
			bw.write("# Logpresso Firewall Ops config file\n");
			bw.write("backend " + backend.name().toLowerCase() + "\n");
			bw.write("api-key " + apiKey + "\n");
			if (proxyAddr != null)
				bw.write("http-proxy " + proxyAddr.getAddress().getHostAddress() + ":" + proxyAddr.getPort() + "\n");
			else
				bw.write("# http-proxy x.x.x.x:8443\n");

			bw.write("\n");
			bw.write("# Prevent accidental IP block\n");
			bw.write("# Network address/CIDR or IP address\n");
			bw.write("[allowlist]\n");
			bw.write("10.0.0.0/8\n");
			bw.write("172.16.0.0/12\n");
			bw.write("192.168.0.0/16\n");
		} catch (IOException e) {
			throw new IllegalStateException("cannot write config file to " + configFile.getAbsolutePath(), e);
		} finally {
			if (bw != null) {
				try {
					bw.close();
				} catch (IOException e) {
				}
			}
		}

		System.out.println("Wrote " + configFile.length() + " bytes to " + configFile.getAbsolutePath());
	}

	private static void installSystemdFile() {
		File dir = IoUtils.getJarDir();
		File serviceFile = new File("/lib/systemd/system/logpresso-firewall-ops.service");
		BufferedWriter bw = null;
		try {
			bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(serviceFile), "utf-8"));
			bw.write("[Unit]\n");
			bw.write("Description=Logpresso Firewall Ops\n");
			bw.write("After=multi-user.target network.target\n");
			bw.write("ConditionPathExists=" + dir.getAbsolutePath() + "/logpresso-firewall-ops.conf\n\n");
			bw.write("[Service]\n");
			bw.write("Type=simple\n");
			bw.write("ExecStart=" + dir.getAbsolutePath() + "/logpresso-firewall-ops start\n");
			bw.write("Restart=on-failure\n");
			bw.write("[Install]\n");
			bw.write("WantedBy=multi-user.target\n");
		} catch (IOException e) {
			throw new IllegalStateException("cannot write systemd file to " + serviceFile.getAbsolutePath(), e);
		} finally {
			if (bw != null) {
				try {
					bw.close();
				} catch (IOException e) {
				}
			}
		}

		System.out.println("Wrote " + serviceFile.length() + " bytes to " + serviceFile.getAbsolutePath());

		try {
			PlatformUtils.execute("systemctl", "daemon-reload");
		} catch (IOException e) {
		}
	}

	public static void uninstall() {
		if (isFirewalldRunning()) {
			new FirewalldConnector().uninstall();
		} else {
			new IptablesConnector().uninstall();
		}

		File serviceFile = new File("/lib/systemd/system/logpresso-firewall-ops.service");
		if (!serviceFile.exists()) {
			System.out.println("Error: service file not found");
			return;
		}

		if (serviceFile.delete()) {
			System.out.println("uninstalled systemd service");
		} else {
			System.out.println("Cannot delete service file " + serviceFile.getAbsolutePath());
		}

		// delete config file
		File dir = IoUtils.getJarDir();
		File configFile = new File(dir, "logpresso-firewall-ops.conf");
		configFile.delete();

		try {
			PlatformUtils.execute("systemctl", "daemon-reload");
		} catch (IOException e) {
		}
	}

	public FirewallConnector getConnector() {
		if (backend == Backend.FIREWALLD)
			return new FirewalldConnector();
		else if (backend == Backend.IPTABLES)
			return new IptablesConnector();
		else
			throw new UnsupportedOperationException();
	}

	public UUID getApiKey() {
		return apiKey;
	}

	public boolean isDebug() {
		return debug;
	}

	public Set<String> getAllowlist() {
		return allowlist;
	}
}
