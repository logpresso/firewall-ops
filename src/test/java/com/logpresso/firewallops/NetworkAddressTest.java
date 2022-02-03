package com.logpresso.firewallops;

import static org.junit.Assert.assertEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Test;

public class NetworkAddressTest {
	@Test
	public void testCidr() {

		NetworkAddress private8 = new NetworkAddress(ip("10.0.0.0"), 8);
		NetworkAddress private12 = new NetworkAddress(ip("172.16.0.0"), 12);
		NetworkAddress private16 = new NetworkAddress(ip("192.168.0.0"), 16);

		assertEquals(ip("10.0.0.0"), private8.getStartIp());
		assertEquals(ip("10.255.255.255"), private8.getEndIp());

		assertEquals(ip("172.16.0.0"), private12.getStartIp());
		assertEquals(ip("172.31.255.255"), private12.getEndIp());

		assertEquals(ip("192.168.0.0"), private16.getStartIp());
		assertEquals(ip("192.168.255.255"), private16.getEndIp());

	}

	private InetAddress ip(String s) {
		try {
			return InetAddress.getByName(s);
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException(s);
		}
	}
}
