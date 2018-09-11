import java.io.FileNotFoundException;
import java.net.UnknownHostException;

import junit.framework.TestCase;

public class FirewallTest extends TestCase {
	Firewall fw;
	
	protected void setUp() throws FileNotFoundException, UnknownHostException {
		fw = new Firewall("C:\\Users\\freni\\eclipse-workspace\\Avenger\\src\\rules.csv");
	}
	
	/**
	 * The below function tests the accept_packet method of the Firewall class
	 */
	public void testAcceptPackets1() {
		assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
	}
	
	public void testAcceptPackets2() {
		assertTrue(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"));
	}
	
	public void testAcceptPackets3() {
		assertTrue(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
	}
	
	public void testAcceptPackets4() {
		assertFalse(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
	}
	
	public void testAcceptPackets5() {
		assertFalse(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"));
	}
	
}
