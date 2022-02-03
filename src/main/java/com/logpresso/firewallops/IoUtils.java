package com.logpresso.firewallops;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

public class IoUtils {
	public static File getJarDir() {
		try {
			File jarPath = new File(
					URLDecoder.decode(IoUtils.class.getProtectionDomain().getCodeSource().getLocation().getPath(), "utf-8"));
			return jarPath.getParentFile();
		} catch (UnsupportedEncodingException e) {
			// unreachable
			throw new IllegalStateException(e);
		}
	}

	public static List<String> loadLines(File f) throws IOException {
		List<String> lines = new ArrayList<String>();
		FileInputStream fis = null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "utf-8"));

			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();

				if (line.startsWith("#") || line.isEmpty())
					continue;

				lines.add(line);
			}

			return lines;
		} finally {
			IoUtils.ensureClose(fis);
			IoUtils.ensureClose(br);
		}
	}

	public static String readLine(File f) throws IOException {
		BufferedReader br = null;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			br = new BufferedReader(new InputStreamReader(fis, "utf-8"));
			return br.readLine();
		} finally {
			IoUtils.ensureClose(br);
		}
	}

	public static void writeLine(File f, String line) throws IOException {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(f);
			fos.write(line.getBytes("utf-8"));
		} finally {
			IoUtils.ensureClose(fos);
		}
	}

	public static void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}
}
