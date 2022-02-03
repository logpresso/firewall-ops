package com.logpresso.firewallops;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class FirewallOpsAgent {
	private Configuration conf;

	public static void main(String[] args) {
		System.out.println("Logpresso Firewall Ops 1.0.0 (2022-02-03)");
		java.security.Security.setProperty("networkaddress.cache.ttl", "30");

		if (args.length == 0) {
			printUsage();
			return;
		}

		String mode = args[0];

		try {
			if ("start".equals(mode)) {
				Configuration c = Configuration.load();
				new FirewallOpsAgent().run(c);
			} else if ("install".equals(mode)) {
				if (args.length < 2) {
					printUsage();
					return;
				}

				UUID apiKey = UUID.fromString(args[1]);
				InetSocketAddress proxyAddr = null;
				if (args.length > 2) {
					String proxy = args[2];
					int p = proxy.indexOf(':');
					if (p < 0) {
						System.out.println("Error: missing proxy port");
						return;
					}

					InetAddress host = InetAddress.getByName(proxy.substring(0, p));
					int port = Integer.parseInt(proxy.substring(p + 1));
					proxyAddr = new InetSocketAddress(host, port);
				}

				Configuration.install(apiKey, proxyAddr);
			} else if ("uninstall".equals(mode)) {
				Configuration.uninstall();
			}
		} catch (Throwable t) {
			System.out.println("Error: " + t.getMessage());
		}
	}

	private static void printUsage() {
		System.out.println("Usage: logpresso-firewall-ops [start|install|uninstall]");
		System.out.println("  start");
		System.out.println("  install [api-key] [http-proxy ip:port]");
		System.out.println("  uninstall");
	}

	public void run(Configuration conf) {
		this.conf = conf;

		int interval = 60000;
		String lastTag = "";

		int i = 0;
		while (true) {
			try {
				if (i++ != 0)
					Thread.sleep(interval);

				lastTag = downloadBlocklist(interval, lastTag);

			} catch (InterruptedException e) {
				// ignore
			} catch (Throwable t) {
				System.out.println("Error: " + t.getMessage());
			}
		}
	}

	private String downloadBlocklist(int interval, String lastTag) {
		System.out.println("Checking Logpresso Watch blocklist..");
		HttpURLConnection conn = null;
		try {
			UUID hostGuid = ensureHostGuid();
			String target = "https://watch.logpresso.com";
			conn = (HttpURLConnection) new URL(target + "/blocklist/policy?host_guid=" + hostGuid + "&tag=" + lastTag)
					.openConnection();
			conn.setConnectTimeout(30000);
			conn.setReadTimeout(30000);
			conn.setRequestProperty("Authorization", "Bearer " + conf.getApiKey());

			int status = conn.getResponseCode();
			if (status == 200) {
				lastTag = updateBlocklist(conn.getInputStream());
			} else if (status == 304) {
				System.out.println("Not modified");
			} else if (status == 503) {
				System.out.println("Error: service unavailable");
			} else if (status == 401) {
				System.out.println("Error: unauthorized api key");
			} else if (status == 404) {
				System.out.println("Error: resource not found");
			} else {
				System.out.println("Error: http error status " + status);
			}

		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			if (conn != null)
				conn.disconnect();
		}

		return lastTag;
	}

	private String updateBlocklist(InputStream is) throws IOException {
		String tag = null;
		List<InetAddress> blocklist = new ArrayList<InetAddress>();
		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(is, "utf-8"));
			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();
				if (line.isEmpty())
					continue;

				if (line.startsWith("# tag ")) {
					tag = line.substring("# tag ".length()).trim();
				} else if (line.startsWith("#")) {
					continue;
				} else {
					blocklist.add(InetAddress.getByName(line));
				}
			}

		} finally {
			IoUtils.ensureClose(br);
		}

		System.out.println("Downloaded " + blocklist.size() + " items. new tag is " + tag);
		conf.getConnector().deployBlocklist(blocklist);

		return tag;

	}

	private static UUID ensureHostGuid() {
		File dir = IoUtils.getJarDir();
		File guidFile = new File(dir, "logpresso-firewall-ops.guid");
		if (guidFile.exists()) {
			try {
				return UUID.fromString(IoUtils.readLine(guidFile));
			} catch (IOException e) {
				throw new IllegalStateException("Cannot read logpresso-firewall-ops.guid file", e);
			}
		} else {
			try {
				UUID newGuid = UUID.randomUUID();
				IoUtils.writeLine(guidFile, newGuid.toString());
				return newGuid;
			} catch (IOException e) {
				throw new IllegalStateException("Cannot write logpresso-firewall-ops.guid file", e);
			}
		}
	}

}
