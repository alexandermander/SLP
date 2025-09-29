#import "@preview/clean-math-paper:0.2.4": *

#set text(hyphenate: true)

#let date = datetime.today().display("[month repr:long] [day], [year]")
#set enum(numbering: "a)")

// Modify some arguments, which can be overwritten in the template call

#page-args.insert("numbering", "1/1")
#text-args-title.insert("size", 2em)
#text-args-title.insert("fill", black)
#text-args-authors.insert("size", 12pt)

#show: template.with(
  title: "Semester Learning Portfolio",
  authors: (
    (name: "Alexander Schandorf Sumczynski"),
  ),
  date: date,
  heading-color: rgb("#03319c"),
  link-color: rgb("#008002"),
  abstract: [this is the apprsikt]
)

#outline(
  depth: 2,
  title: [Contents]
)

#pagebreak()

== Introduction for typst

$
  sum_(k=1)^n k = (n(n+1)) / 2
$<equation>

$
  exp(x) = sum_(n=0)^oo (x^n) / n!
$

As we can see, it is not numbered.

== Theorems

The template uses #link("https://typst.app/universe/package/great-theorems/")[`great-theorems`] for theorems. Here is an example of a theorem:

#theorem(title: "Example Theorem")[
  This is an example theorem.
]<th:example>
#proof[
  This is the proof of the example theorem.
]

We also provide `definition`, `lemma`, `remark`, `example`, and `question`s among others. Here is an example of a definition:

#definition(title: "Example Definition")[
  This is an example definition.
]

#question(title: "Custom mathblock?")[
  How do you define a custom mathblock?
]

#let answer = my-mathblock(
  blocktitle: "Answer",
  breakable: true
  //bodyfmt: text.with(style: "italic"),
)

#let notes  = my-mathblock(
  blocktitle: "Notes",
  breakable: true
)
//

#let assignment  = my-mathblock(
  blocktitle: "Assignment",
  //bodyfmt: text.with(style: "bold"),
)
//
//#answer[
//  You can define a custom mathblock like this:
//  ```typst
//  #let answer = my-mathblock(
//    blocktitle: "Answer",
//    bodyfmt: text.with(style: "italic"),
//  )
//  ```
//]
//
////To get a bibliography, we also add a citation @Cooley65.
//
//#lorem(50)
//
//If you have appendices, you can add them after `#show: appendices`. The appendices are started with an empty heading `=` and will be numbered alphabetically. Any appendix can also have different subsections.
//#lorem(20)
//
//


= Authentication + Link Layer Security: Lecture One

== Notes leacure one

#notes(title:"Remote User - Authenticationusing Asymmetric Encryption")[


$
"A" -> "AS": & italic("ID")_A || italic("ID")_B \ 
"AS" -> "A": & "E"(italic("PR")_italic("as"), [italic("ID")_A || italic("PU")_a || T]) || "E"(italic("PR")_italic("as"), [italic("ID")_B || italic("PU")_b || T]) \
"A" -> "B": & "E"(italic("PR")_italic("as"), [italic("ID")_A || italic("PU")_a || T]) || "E"(italic("PR")_italic("as"), [italic("ID")_B || italic("PU")_b || T]) || "E"(italic("PU")_b, "E"(italic("PR")_a, [K_s || T]))
$


$
"A" -> "KDC": & italic("ID")_A || italic("ID")_B \
"KDC" -> "A": & "E"(italic("PR")_"auth", [italic("ID")_B || italic("PU")_b]) \
"A" -> "B": & "E"(italic("PU")_b, [N_a || italic("ID")_A]) \
"B" -> "KDC": & italic("ID")_A || italic("ID")_B || "E"(italic("PU")_"auth", N_a) \
"KDC" -> "B": & "E"(italic("PR")_"auth", [italic("ID")_A || italic("PU")_a]) || "E"(italic("PU")_b, "E"(italic("PR")_"auth", [N_a || K_s || italic("ID")_A || italic("ID")_B])) \
"B" -> "A": & "E"(italic("PU")_a, [N_b || "E"(italic("PR")_"auth", [N_a || K_s || italic("ID")_A || italic("ID")_B])]) \
"A" -> "B": & "E"(K_s, N_b)
$


]

== Network Security Assignment part 1

#assignment[ 
  #colbreak()
*Objective:*
  Research and write a concise paragraph about techniques used to mitigate ARP spoofing and Spanning
Tree Protocol (STP) attacks (Layer 2 attacks). Please write details on how the chosen technique detects
and prevents the attack, and any potential limitations they may have in a network environment. Please
also mention your opinion about the complexity of the techniques you found. 
]



#answer(title: "ARP Spoofing Mitigation", width: auto)[

#enum(
  enum.item()[
    *Static ARP entries:* Using static entries in the ARP
		table means the IP–MAC mapping cannot be altered by ARP
		spoofing. The limitation is that when a new device joins the
		network, its IP–MAC pair must be manually added to the ARP
		tables of the relevant devices. its nice that i can setup this
		in a static mac adreses but let say that i ahve to do this for
			a capnut and maitnign this so alle vesties are update date
			and 
		],
  enum.item()[
			*Dynamic ARP Inspection (DAI):*Is a technique where the
			switches are configured to map each device in the network
			to a specific IP–MAC pair. If an ARP spoofing attack
			occurs, then the switch detects that there is an
			unauthorized ARP request. The limitation of this method is
			that the switch must be set up with DAI and must be a
			supported type of switch. This is a better solution than
			the static assigning since there is a dynamic system in
			the switches that can help manage the ARP spoofing attacks
			instead of manually setting each device. 
		],
	enum.item()[

		*XArp:* Is an anti-spoofing software that can detect if an ARP
			spoofing attack is being performed on a target system that
			has installed the XArp on the system, and this is the
			limitation—that I have to install the XArp and make sure
			that it’s up to date and has no vulnerabilities in this
			program. 
	]
) ]

#v(2em)

#answer(title: "STP Attacks Mitigation", width: auto)[

#enum(

	enum.item[
			* BPDU Guard* is a security feature that automatically
			puts a PortFast-configured access port into an
			error-disabled state when it receives any BPDU, protecting
			the STP domain from rogue switches or misconfiguration
		],

	enum.item[

			*Root Guard* is a security feature that prevents non-root
			ports from becoming root ports by placing them into a
			root-inconsistent state if they receive superior BPDUs,
			ensuring the STP topology remains stable and protecting
			the network from rogue root bridge elections.

		]
)
]

== Network Security Assignment part 2
#assignment[ 
  #colbreak()
*Objective:*
  In this assignment we are going to emulate a Man-in-the-Middle (MITM) attack using this network
topology.

As an attacker we should connect to the switch to be able to communicate with the target/victim
hosts. From now on, we refer to our two targets hosts as victims.
]

#v(2em)

#answer(title: "Experiencing Layer 2 attacks", width: auto)[
	#enum(
		enum.item[

			The setup I have is two lightweight Lubuntu systems and a
			Kali Linux where the Man-in-the-Middle attack will be
			performed. The network is connected to a NAT network
			through my local machine. 
			#figure(
			  image("screen/Screenshot 2025-09-19 143715.png", width: 120%),
			  caption: [
				The two Lubuntu machines
			  ],
			
			) <fig:lubuntu>

			In @fig:lubuntu there are the two lightweight
			Lubuntu machines. The right machine is performing a ping
			to the other machine (on the left), and the left machine
			is running the arp -a command to show the devices that are
			running on this NAT network.

		],

		enum.item[

			The next step is to perform the ARP spoofing attack on the
			two targets. To do that, on the Kali machine I use the
			program Ettercap to scan for the two targets and select
			them as victims, where it will then perform the spoofing
			attack.

			#figure(
			  image("screen/Screenshot 2025-09-19 143910.png", width: 120%),
			  caption: [
				The two Lubuntu machines
			  ],
			
			) <fig:wire>

			In @fig:wire, it shows how the attack is under execution,
			where on the left is the Lubuntu machine that performs a
			ping to the other Lubuntu machine (on the right). But
			since we have created a Man-in-the-Middle between the two
			targets, the traffic can now be seen on the Kali machine,
			as shown in the image. In this, Wireshark is capturing the
			traffic between the two machines.

		]
	)

]


= TCP/IP Internet Layer Security

== Assignment Experiencing IPsec (Group) part one

Group:
\ Alexander Sumczynski, Marcus Kolbe, Luca, 

We did the this exesice in bash and asnwed with a scpript whre we
cateuted alle the files thing in the one singen scpript, to see the
scpript that go to @bash-network1


#pagebreak()

== Assignment VPN part two

#v(1em)


#text(strong("SSL/TLS VPNs vs IPsec:") )

SSL/TLS VPNs are a method to establish a VPN connection over the TLS
protocol. They use the HTTPS protocol to communicate and encrypt data.
The way it works is that the client’s packets are encapsulated inside
TLS encryption and sent to the VPN server. The VPN server decrypts the
packets and forwards the traffic to the final destination on behalf of
the client. The response from the destination server is then returned
to the VPN server, which re-encapsulates it in TLS and sends it back
to the client. Since SSL/TLS VPNs operate over HTTPS, they are
firewall-friendly. The SSL/TLS VPN protocol operates at the
application layer. Comparing this protocol with IPsec. IPsec
operates at the network layer, and therefore the protocol needs to
establish a key-exchange method. There are two main methods: Internet
Key Exchange (IKEv1) and Internet Key Exchange version 2 (IKEv2).
Compared to IPsec, SSL/TLS VPNs are more effective at bypassing normal
firewalls, since IPsec traffic can sometimes be blocked or require
extra configuration.

#text(strong("WireGuard  vs IPsec:") )

The WireGuard is a more modern VPN. It uses the following protocols:

- ChaCha20 for symmetric encryption, authenticated with Poly1305,
- Curve25519 for key exchange,
- SipHash24,
- BLAKE2s for hashing,
- HKDF for key derivation.


One of the features that WireGuard is primarily designed for is its
integration in the Linux kernel, which makes installation and setup
easy. WireGuard uses Curve25519 to derive the key-exchange method.
Another technique that WireGuard uses is frequent rotation of the
session keys, which makes the protocol more secure while still
maintaining the fast connection that is one of the key features of
WireGuard.

To compare this protocol to IPsec: both operate in the same network
stack at Layer 3, but WireGuard has a much smaller code base, whereas
IPsec has a much larger code base that makes IPsec more  configurable
and able to run on most operating systems. This lean design also means
WireGuard is easier to audit and maintain, reducing the potential
attack surface compared to the more complex IPsec implementation.
While IPsec supports a wide range of cipher suites and authentication
methods, which contributes to its flexibility, this complexity can
also lead to more configuration errors and higher administrative
overhead. WireGuard, by contrast, focuses on a fixed set of modern
cryptographic primitives, providing strong security with minimal
configuration and typically faster connection setup.

//#bibliography("bibliography.bib")
//

#pagebreak()

== Appendix section
//
#show: appendices

= Bash code Network Layer Security part one
#label("bash-network1")

```bash
#!/usr/bin/env bash

NODE1="192.168.122.77"
NODE1_USER="alice"
NODE2="192.168.122.122"
NODE2_USER="bob"

TIME=5

## No encryption

# Stop strongswan on machines
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"

# Wait a moment
sleep 1

# Start capture
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "tshark -w unenc_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "tshark -w unenc_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &

# Wait a moment
sleep 1

# Make traffic
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "curl http://192.168.200.153" &

# Wait
sleep $(( $TIME + 2 ))

# Get capture files
sshpass -p "password" scp ${NODE1_USER}@${NODE1}:unenc_capture.pcap node1_unenc_capture.pcap
sshpass -p "password" scp ${NODE2_USER}@${NODE2}:unenc_capture.pcap node2_unenc_capture.pcap

## IKE handshake

# Start capture
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "tshark -w ikehandshake_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "tshark -w ikehandshake_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &

# Wait a moment
sleep 1

# Start strongswan on machines
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S systemctl start strongswan-starter.service" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S systemctl start strongswan-starter.service" &

# Wait
sleep $(( $TIME + 2 ))

# Get capture files
sshpass -p "password" scp ${NODE1_USER}@${NODE1}:ikehandshake_capture.pcap node1_ikehandshake_capture.pcap
sshpass -p "password" scp ${NODE2_USER}@${NODE2}:ikehandshake_capture.pcap node2_ikehandshake_capture.pcap

## Get encrypted traffic

# Start capture
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "tshark -w esp_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "tshark -w esp_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &

# Wait a moment
sleep 1

# Make traffic
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "curl http://192.168.200.153" &

# Wait
sleep $(( $TIME + 2 ))

# Get capture files
sshpass -p "password" scp ${NODE1_USER}@${NODE1}:esp_capture.pcap node1_esp_capture.pcap
sshpass -p "password" scp ${NODE2_USER}@${NODE2}:esp_capture.pcap node2_esp_capture.pcap

## Get Tunnel vs Transport capture (tunnel is default, so we do transport here. (with fuckery))

# Bring the ipsec tunnel down
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"

# Wait a moment
sleep 1

# Change the config file
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S sed -i 's/type=tunnel/type=transport/' /etc/ipsec.conf "
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S sed -i 's/type=tunnel/type=transport/' /etc/ipsec.conf"

# Wait a moment
sleep 1

# Bring up ipsec again
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S systemctl start strongswan-starter.service" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S systemctl start strongswan-starter.service" &

# Wait a moment
sleep 1

# Start capture
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "tshark -w transport_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "tshark -w transport_capture.pcap -i enp7s0 & sleep ${TIME} && killall tshark" &

# Wait a moment
sleep 1

# Make traffic
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "curl http://192.168.200.153" &

# Wait
sleep $(( $TIME + 2 ))

# Get capture files
sshpass -p "password" scp ${NODE1_USER}@${NODE1}:transport_capture.pcap node1_transport_capture.pcap
sshpass -p "password" scp ${NODE2_USER}@${NODE2}:transport_capture.pcap node2_transport_capture.pcap

# Stop ipsec again
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S systemctl stop strongswan-starter.service"

# Revert the change
sshpass -p "password" ssh ${NODE1_USER}@${NODE1} "echo 'password' | sudo -S sed -i 's/type=transport/type=tunnel/' /etc/ipsec.conf"
sshpass -p "password" ssh ${NODE2_USER}@${NODE2} "echo 'password' | sudo -S sed -i 's/type=transport/type=tunnel/' /etc/ipsec.conf"

```




