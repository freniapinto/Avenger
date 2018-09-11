import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Firewall {
	static Set<Packet> rules = new HashSet<>();

	public Firewall(String path) throws FileNotFoundException, UnknownHostException {
		int start_port = 0;
		int end_port = 0;
		int start_ip = 0;
		int end_ip = 0;
		Scanner sc = new Scanner(new File(path));

		while (sc.hasNext()) {
			String text = sc.next();

			String[] line = text.split(",");
			if (!text.contains("-")) {
				rules.add(new Packet(line[0], line[1], Integer.parseInt(line[2]), line[3]));
			} else {
				if (line[2].contains("-")) {
					String[] ports = line[2].split("-");
					start_port = Integer.parseInt(ports[0]);
					end_port = Integer.parseInt(ports[1]);
				} else {
					start_port = Integer.parseInt(line[2]);
					end_port = Integer.parseInt(line[2]);
				}
				/*
				if (line[3].contains("-")) {
					String[] ips = line[3].split("-");
					start_ip = ByteBuffer.wrap(InetAddress.getByName(ips[3]).getAddress()).getInt();
					end_ip = ByteBuffer.wrap(InetAddress.getByName(ips[3]).getAddress()).getInt();
				} else {
					start_ip = ByteBuffer.wrap(InetAddress.getByName(line[3]).getAddress()).getInt();
					end_ip = ByteBuffer.wrap(InetAddress.getByName(line[3]).getAddress()).getInt();
				} */

			}

			for (int i = start_port; i <= end_port; i++)
				/* for (int j = start_ip; j <= end_ip; j++)
					rules.add(new Packet(line[0], line[1], i,
							InetAddress.getByName(Integer.toString(j)).getHostAddress()));*/
				rules.add(new Packet(line[0], line[1], i, line[3]));
				
		}
		sc.close();
	}

	/**
	 * Returns True if a rule exists with the param properties, False otherwise
	 * 
	 * @param direction
	 *            String: “inbound” or "outbound"
	 * @param protocol
	 *            String: "tcp" or "udp"
	 * @param port
	 *            int : [1-65535] range
	 * @param ip_address
	 *            String: well-formed IPv4 address
	 * @return boolean
	 */
	public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
		return new Packet(direction, protocol, port, ip_address).validatePacket(rules);
	}
}

class Packet {
	String direction;
	String protocol;
	int port;
	String ip_address;

	public Packet(String direction, String protocol, int port, String ip_address) {
		this.direction = direction;
		this.protocol = protocol;
		this.port = port;
		this.ip_address = ip_address;
	}

	@Override
	public int hashCode() {
		return direction.hashCode() + protocol.hashCode() + ip_address.hashCode() + port;
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof Packet && this.direction.equals(((Packet) o).direction)
				&& this.protocol.equals(((Packet) o).protocol) && this.port == ((Packet) o).port
				&& this.ip_address.equals(((Packet) o).ip_address);
	}

	@Override
	public String toString() {
		return this.direction + " " + this.protocol + " " + this.port + " " + this.ip_address;
	}

	boolean validatePacket(Set<Packet> rules) {
		return rules.contains(this);
	}
}
