#import "@preview/clean-math-paper:0.2.4": *

#let date = datetime.today().display("[month repr:long] [day], [year]")

// Modify some arguments, which can be overwritten in the template call
#page-args.insert("numbering", "1/1")
#text-args-title.insert("size", 2em)
#text-args-title.insert("fill", black)
#text-args-authors.insert("size", 12pt)

#show: template.with(
  title: "Semester Learning Portfolio ",
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

= Introduction
#lorem(20)

= Equations

== leture one


The template uses #link("https://typst.app/universe/package/i-figured/")[`i-figured`] for labeling equations. Equations will be numbered only if they are labelled. Here is an equation with a label:

$
  sum_(k=1)^n k = (n(n+1)) / 2
$<equation>

We can reference it by `@eq:label` like this: @eq:equation, i.e., we need to prepend the label with
`eq:`. The number of an equation is determined by the section it is in, i.e. the first digit is the
section number and the second digit is the equation number within that section.

Here is an equation without a label:

$
  exp(x) = sum_(n=0)^oo (x^n) / n!
$

As we can see, it is not numbered.

= Theorems

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
  bodyfmt: text.with(style: "italic"),
)

#answer[
  You can define a custom mathblock like this:
  ```typst
  #let answer = my-mathblock(
    blocktitle: "Answer",
    bodyfmt: text.with(style: "italic"),
  )
  ```
]

Similar as for the equations, the numbering of the theorems is determined by the section they are in. We can reference theorems by `@label` like this: @th:example.

To get a bibliography, we also add a citation @Cooley65.

#lorem(50)

#bibliography("bibliography.bib")

// Create appendix section
#show: appendices
=

If you have appendices, you can add them after `#show: appendices`. The appendices are started with an empty heading `=` and will be numbered alphabetically. Any appendix can also have different subsections.

== Appendix section

#lorem(100)
