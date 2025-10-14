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
  abstract: [this is the firewall-friendly]
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

#text(strong("Task 1:") )
In the firt part of the start is setting up the two system ubunto severs that suold communicate
toghter, 

#figure(
  image("screen/bobpingalice.png", width: 100%),
  caption: [
  The two Lubuntu machines: alice and bob
  ],

) <fig:bobpingalice>

In @fig:bobpingalice shows how after sinnign up the config files that alcie macinge can ping
the bob virtuel maicnge 
\
#text(strong("Task 2 Pre-IPsec Capture:") )
\

In Task 2, setting up the capture traffic between the two virtual machines will first happen after
some traffic has been passed through the system. Observing these packets being sent is just normal
traffic that is not encrypted or anything. I can see the GET request to the Bob machine that is
hosting an Apache2 service, so all the TCP handshakes and the GET/response is plain text

#text(strong("Task 3 Capturing IKE:") )
\

Now starting tshark, then launching the IPsec services. This will allow the capture of the IKE (Internet
Key Exchange) packets. The IPsec service is stopped first so that the initial packets can be captured.

#question(title: "What parameters are negotiated during the IKE exchange?", width: auto)[
  While observing the negotiation, several parameters are mentioned: an integrity algorithm,
  pseudo-random function, and the Diffie-Hellman key exchange. These different values can be seen in
  the payload packed
]

#text(strong("Task 4 Capturing ESP:") )
\

#question(title: "What differences do you notice between the captured ESP packets and the plaintext packets from Task 2?", width: auto)[
Observing the packets from Task 2 that are in plaintext, and then the packets that are
encapsulated inside an ESP packet, the information is encrypted and scrambled.
]

#question(title: "Why is the payload data not visible in the ESP packet? (put screenshots on your
  report to show that)", width: auto)[

The payload data is not visible in the ESP packet because IPsec’s Encapsulating Security Payload (ESP) protocol encrypts it. 

#figure(
  image("screen/eps.png", width: 100%),
  caption: [
    ESP traffic
  ],
) <fig:esp>

  As seen in the @fig:esp is the is the screen shot of the ESP filter

]

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
= Transport Layer Security (TLS) + Secure Shell (SSH)


== Assignment TLS Cipher Suite (Individual) + Analyze their components

*Review Valid Combinations of TLS Cipher Suites mentioned in the slides*

- *Assignment* #emph['Study the provided list of valid TLS
  cipher suites']: \

#enum(
	enum.item[
		*Key Exchange*
		\
		In the 10 valid TLS cipher suites, three different key exchange
		methods are used: #emph[RSA, DHE, ECDHE]. RSA is a method
		where the two parties use public keys to encrypt the symmetric
		key that both sides will use. DHE (Diffie-Hellman Ephemeral)
		is a technique where the two parties use the Diffie-Hellman
		algorithm to derive a shared secret key that will be used to
		encrypt the messages they send to each other. ECDHE (Elliptic
		Curve Diffie-Hellman Ephemeral) is another method to derive a
		shared secret key, but this one uses elliptic curve
		cryptography to achieve stronger security with smaller key
		sizes. 

	],
	enum.item[
		*Authentication*
		\

		RSA is a public-key algorithms. That can be used for
		authentication of the server, by signing secure digital
		messages and certificates. The security of RSA relies on the

		ECDSA (Elliptic Curve Digital Signature Algorithm) works in a
		similar to  the RSA way but is based on elliptic-curve
		cryptography.
	],
	enum.item[
		*Encryption Algorithm + Mode*

		AES is a symmetric-key encryption algorithm and is the one
		used most often in the valid TLS cipher suites from the
		slides. AES is a block cipher that can use three key lengths:
		128-bit, 192-bit, or 256-bit. The mode defines how the blocks
		of data are processed. Common modes in TLS include CBC (Cipher
		Block Chaining) and GCM (Galois/Counter Mode). CBC mode
		encrypts each block based on the previous one, while GCM mode
		provides both encryption and built-in integrity verification.

	],

enum.item[
		*MAC Function*
		\
		Message Authentication is a method used to verify that a message
		truly comes from the sender the client is communicating with.
		Integrity ensures that the parties in a communication channel
		can confirm that none of the messages have been tampered with
		during transmission. In TLS, this is achieved using a MAC
		function such as SHA256 or SHA384, which creates a unique
		fingerprint for each message. If the message changes in any
		way, the fingerprint no longer matches, and the receiver can
		detect that the data has been altered.
	]

)

*Design 3 “Impossible” Cipher Suites + Justify
Each Invalid Combination *:

#enum(
    enum.item[
	  *TLS_DH_DSA_WITH_AES_128_CBC_SHA:* 
	  \  
		This combination is invalid because the Diffie-Hellman (DH)
		and the DSA are not compatible for key exchange and
		authentication, since DSA is designed only to sign messages.
		Therefore, there is no authentication in this cipher suite. 

    ],

    enum.item[
      *TLS_AES_RSA_WITH_ECDH_GCM_SHA256:* 
      \  
		AES is a symmetric encryption algorithm and cannot be used for
		key exchange, while ECDH is an asymmetric key exchange method.
		Combining them in this order makes the suite structure
		incorrect and therefore an impossible combination in TLS. 
    ],

    //enum.item[
    //  *TLS_AES_RSA_WITH_ECDH_GCM_SHA256:* 
    //  \  
    //]

)

//- Review Valid Combinations of TLS Cipher Suites mentioned in the slides:
//• Study the provided list of valid TLS cipher suites.
//• Analyze their components: key exchange method, authentication algorithm, encryption
//algorithm + mode, and MAC function.
//- Design 3 “Impossible” Cipher Suites:
//• Propose three combinations of TLS cipher suite components that are invalid or impossible in
//real-world TLS implementations.
//• Use the following format for each:
//TLS_<KeyExchange>_<Auth>_WITH_<Encryption>_<MAC>
//- Justify Each Invalid Combination:
//For each of your 3 impossible suites, write a short explanation (~100–150 words) covering:
//• Why this combination does not work.
//• Whether it is deprecated, insecure, or never defined in standards.

#pagebreak()

== Assignment  SSH MITM attack (Individual)

First, to perform the ARP spoofing attack, the
Man-in-the-Middle attack has to be prepared too,
so that Ettercap GUI can be used to set the two
targets and then start the Man-in-the-Middle.


#figure(
  image("screen/thredLeache/screenshot_2025-10-06_18-28-01.png", width: 100%),
  caption: [
  Ettercap GUI starts the MITM
  ],
) <fig:ettercap_kali>




#figure(
  image("screen/thredLeache/screenshot_2025-10-06_18-16-44.png", width: 100%),
  caption: [
  Bob the client
  ],
) <fig:b_clinet>

#figure(
  image("screen/thredLeache/screenshot_2025-10-06_18-17-48.png", width: 100%),
  caption: [
    Alice the server
  ],
) <fig:a_server>

As @fig:b_clinet and @fig:a_server show, the
server and the client have changed the MAC address
to the Kali machine’s MAC.

\
#pagebreak()

Now the Man-in-the-Middle SSH can be performed
with the following command:
```bash
$ ssh-mitm server --remote-host 192.168.122.212 
```
#figure(
  image("screen/thredLeache/screenshot_2025-10-06_18-23-53.png", width: 100%),
  caption: [
    ssh-mitm
  ],
) <fig:a_serveaar>

After the successful attack, 'ssh-mitm' showed
some CVEs. I think these CVEs are vulnerabilities
that can be exploited to make a more persistent
attack. I also noticed that when I tried to
connect to Alice (the server) again, I got an SSH
warning saying "there's an eavesdropper, possibly
a Man-in-the-Middle attack".

Exploring the hijack, I saw that I could enter the
SSH session and start typing and using the shell
that Bob had just started. And the typing was also
showed on the Bob machine.


#pagebreak()

= WiFi security

== Assignment WiFi (Group)

I did the group assignment, but when we wanted to
deauth the beacon WiFi, there were too many access
points, so we could not do the deauth from our
Raspberry Pi.

So I decided to do the assignment individually,
without the WiFi Pineapple, since I have my own
internet adapter that can do monitor mode.

To set up for the assignment, I used a Raspberry
Pi to create a hotspot. The commands I used were:

```bash 
$ sudo nmtui
```

After setting up the hotspot, I connected to the Raspberry Pi with my laptop and mobile phone to start traffic and start pinging each other.
While the traffic was running, I started the ALFA
adapter in monitor mode and started airodump-ng to
capture the traffic, with the following commands:

```bash 
$ sudo ifconfig wlan1 down 
$ sudo iwconfig wlan1 mode monitor 
$ sudo ifconfig wlan1 up 
# to check which channel the access point is on 
$ sudo airodump-ng wlan1 -c <channel>
```
Now that the traffic was captured, the next step
is to deauth the connected clients from the
hotspot to capture the handshake. 

```bash
$ sudo airodump-ng --bssid <bssid> -c <channel> -w capture wlan1 
$ sudo aireplay-ng --deauth 100 -a C6:60:AD:1A:5E:38  wlan1
```

#figure(
  image("screen/forhLeach/screenshot_2025-10-14_11-05-51.png", width: 100%),
  caption: [
    Captured handshake
  ],

) <fig:cature>

In @fig:cature, shows that the handshake is
captured and now the next step is to try to crack
the password with the tool John the Ripper. But
before cracking the password, the capture file
have to be converted to a hash file that John can
accept.

```bash
$ wpapcap2john SanderHand-01.cap > SanderHandJohon.john
$ john  SanderHandJohon.john
```

#figure(
  image("screen/forhLeach/screenshot_2025-10-14_11-08-44.png", width: 100%),
  caption: [
    Captured handshake
  ],

) <fig:crak>


As @fig:crak shows, the password is cracked and it
took less then 1 second to crack the password,
since the password is a weak password.

#pagebreak()

//4.4 Assignment WiFi Attack Names
== Assignment Wi-Fi Attack Names

*Man-in-the-middle attacks* \
This is an attack where the attacker places
themselves between two targets that are
communicating. The attacker can then intercept,
modify, block the communication, or simply just
listen to it. The attacker can perform an *SSL
hijack* attack that downgrades the HTTPS protocol
to HTTP, allowing them to see all communication in
plain text. For example, the attacker downgrades
the HTTPS login page to HTTP, and now they can see
the username and password being sent.
\ *DNS spoofing* is a technique where the attacker has
established a man-in-the-middle attack, and can
then intercept DNS requests and respond with a
malicious IP address. This allows them to redirect
the user to a fake website — for instance, a fake
Facebook login page. Even if there is an OTP
(one-time password), the attacker can still design
the website to look identical to the real Facebook
page. When the user enters their username and
password, the attacker can then perform an account
takeover.

#v(1em)
\
*Network injection — router / access point compromise*\
An attacker may target a Wi-Fi router or access
point by exploiting firmware vulnerabilities,
weak/default credentials, or try to inject
malicious code to execute unauthorized commands
gain access. Once the attacker gains
administrative access they can modify firmware
logic or configuration so the device behaves
according to the attacker’s wishes: capturing and
logging all passing traffic, altering DNS
responses, injecting malicious scripts into HTTP
pages, or creating persistent backdoors for later
access. 
\ 
*Deauthentication attacks* are a type of attack
where the attacker sends deauthentication frames
to the target device, forcing it to disconnect and
after the disconnection, the target device will
try to reconnect to the access point, with a WPA
handshake. The attacker can then capture the
handshake and try to crack the password.

#pagebreak()

== Appendix section

#show: appendices
