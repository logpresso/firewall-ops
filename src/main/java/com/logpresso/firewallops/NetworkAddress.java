package com.logpresso.firewallops;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class NetworkAddress {
	private InetAddress addr;
	private int cidr;
	private long start;
	private long end;

	public NetworkAddress(InetAddress addr, int cidr) {
		long mask = getMask(cidr);

		this.start = toLong(addr) & mask;
		this.end = (start | ~mask) & 0xffffffffL;
		this.addr = toIp(start);
		this.cidr = cidr;
	}

	public InetAddress getStartIp() {
		return toIp(start);
	}

	public InetAddress getEndIp() {
		return toIp(end);
	}

	private static InetAddress toIp(long ip) {
		byte b1 = (byte) ((ip >> 24) & 0xff);
		byte b2 = (byte) ((ip >> 16) & 0xff);
		byte b3 = (byte) ((ip >> 8) & 0xff);
		byte b4 = (byte) (ip & 0xff);

		byte[] b = new byte[] { b1, b2, b3, b4 };
		try {
			return InetAddress.getByAddress(b);
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("unreachable");
		}
	}

	private static long getMask(int cidr) {
		long mask = 0;
		for (int i = 0; i < cidr; i++)
			mask |= 1 << (31 - i);

		return mask;
	}

	public boolean contains(InetAddress ip) {
		long v = toLong(ip);
		return start <= v && v <= end;
	}

	private long toLong(InetAddress ip) {
		byte[] b = ip.getAddress();
		return (((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff)) & 0xffffffffL;
	}

	@Override
	public String toString() {
		return String.format("%s/%d (%d~%d)", addr.getHostAddress(), cidr, start, end);
	}

}
