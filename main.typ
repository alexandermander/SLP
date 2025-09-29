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

== leacure notes

#notes(title: "Layer/Network Layer", weight: "bold")[
  this is the text

  //\
  //#text(size: 1.2em, weight: "bold")[ Layer/Network Layer ]
  //\
]


//#bibliography("bibliography.bib")
//
//== Appendix section
//
//#show: appendices
//
//#lorem(100)



