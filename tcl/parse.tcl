eval_in ::parse
fluid vars
proc prog1 {x script} {uplevel 1 $script; return $x}
proc defp {name arg_list body} {
  uplevel 1 [list proc $name [lappend arg_list in_var] "upvar 1 \$in_var in; $body"]
}
namespace export defp
  
defp err {msg} {error [list $in $msg] "" {PARSE ERROR}}
defp fail {msg} {error [list $in $msg] "" {PARSE FAIL}}
defp expected {thing} {fail "expected $thing" in}

defp eof {} {if {![cursor eof $in]} {expected eof in}}
defp do {p} {{*}$p in}
defp cat {ps} {lmap p $ps {{*}$p in}}
defp ret {x} {return $x}
defp code {script} {eval $script}
defp >> {p script} {set x [{*}$p in]; eval $script}
defp = {p val} {prog1 $val {{*}$p in}}
defp flat {p} {lflatten [{*}$p in]}
defp app {p prefix} {{*}$prefix [{*}$p in]}
defp exp {e} {{*}[memo ::parse::compile_parser $e] in}
defp guard {p} {set in2 $in; return [{*}$p in2]}
defp not {p} {set n $in; try {{*}$p n} trap {PARSE FAIL} {} return; fail "not failed" in}
defp ref {n} {{*}[vars get $n] in}
defp ind {p} {alt [list [list = $p 1] {ret 0}] in}
defp name {n p} {upvar 2 $n v; set v [{*}$p in]}
defp seq {ls} {
  set selected 0
  set res {}
  foreach {dir p} $ls {
    set r [{*}$p in]
    switch $dir {
      ign {}
      inl {lappend res {*}$r}
      sel {set selected 1; set sel $r}
      - {lappend res $r}
      default {error "unknown seq directive $dir"}
    }
  }
  if {$selected} {return $sel}
  return $res
}
defp rep_onto {p ls} {
  set save $in
  try {
    while 1 {lappend ls [{*}$p in]; set save $in}
  } trap {PARSE FAIL} {} {
    set in $save
    return $ls
  }
}
defp rep {p} {rep_onto $p {} in}
defp rep1 {p} {rep_onto $p [list [{*}$p in]] in}
defp alt {ps} {
  set ok 1
  set save $in
  foreach p $ps {
    try {return [{*}$p in]} trap {PARSE FAIL} r {set ok 0; set in $save}
  }
  if {!$ok} {error $r "" {PARSE FAIL}}; # rethrow last fail
}
defp commit {p} {
  try {return [{*}$p in]} trap {PARSE FAIL} {r} {error $r "" {PARSE ERROR}}
}
defp opt {p} {alt [list [list app $p list] {ret ""}] in}
defp rep1sep {p sep} {rep_onto [list seq [list - $sep sel $p]] [list [{*}$p in]] in}
defp repsep {p sep} {alt [list [list rep1sep $p $sep] {ret ""}] in}
defp check {p e expect} {set x [{*}$p in]; if $e {return $x}; expected $expect in}
defp predict {p t} {
  variable pred
  set pred(pos) $in
  {*}[tree getor $t [set pred(val) [{*}$p pred(pos)]] {fail predict}] in
}
defp _lmatch {p t} {
  set rest [lassign [set all [{*}$p in]] head]
  lcase [tree getor $t $head ""] {
    {pat expr} {
      set ls ""
      foreach elt $pat val $rest {lappend ls $elt [list ret $val]}
      vars let * [list ret $all] _ [list ret $head] {*}$ls {{*}$expr in}
    }
    {} {fail lmatch in}
  }
}
defp predval {} {variable pred; set in $pred(pos); return $pred(val)}
defp peekchar {} {return [cursor index $in]}
  
# Note: need to add ^ to beginning of expression unless you want to
# skip past arbitrary input before the match. Adding it here would
# prevent compiled regexps from being cached. The parser definition
# language has the r{...} construct which does automatically add ^.
defp rex {exp thing} {
  if {[regex::match -cursor -- $exp $in m]} {
    return [prog1 [cursor range {*}$m] {set in [lindex $m 1]}]
  }
  expected $thing in
}
defp anychar {} {
  if {[cursor eof $in]} {expected "char" in}
  return [cursor consume in 1]
}
defp char {chars} {
  if {[string first [set c [cursor index $in]] $chars] != -1} {return [cursor consume in 1]}
  if {[string length $chars] == 1} {expected $chars in}
  expected "one of \"$chars\"" in
}
defp notchar {chars} {
  if {[string first [cursor index $in] $chars] != -1} {expected "not $chars" in}
  anychar in
}
defp exact {str} {
  if {[cursor consume in [string length $str]] ne $str} {expected \"$str\" in}
  return $str
}
defp brace_string {} {
  if {[cursor index $in] ne "\{"} {expected "braced string" in}
  return [parse_braces in]
}
defp command_subst {} {
  if {[cursor index $in] ne "\["} {expected "command substitution" in}
  cursor incr in
  set cmd [parse_command 1 in]
  if {[string index $cmd end] ne "\]"} {expected "\]" in}
  return [string range $cmd 0 end-1]
}

# Use the combinators defined so far to bootstrap a more pleasant
# language for writing parsers. Start with a simple lexer.
variable punct_RE {->|=>|>>|[{}()|&,:*+?\[\]/$@%=.-]}
variable ident_RE {[a-zA-Z_]\w*}
variable number_RE {0|-?[1-9][0-9]*}
variable quoted_RE {b?'[^']*'|\"[^\"]*\"|<[^>]*>}
variable token_RE "^(?:$punct_RE|$quoted_RE|$ident_RE|$number_RE)"
defp ws {} {rex {^(?:\s+|/\*(?:[^*]|\*+[^*/])*\*+/)*} "" in}
defp get_token {} {
  variable token_RE
  variable ident_RE

  ws in
  set tok [rex $token_RE token in]

  # Compiled to jump table. Here is an interesting fact: using
  # backslash rather than "" or {} to escape a case label will cause
  # jump table compilation to fail. Unfortunately, though, Emacs
  # doesn't like {"}. No idea why Tcl won't \-escape simple words in
  # compilation.
  switch [set c [string index $tok 0]] {
    [ {return lbracket} ] {return rbracket}
    "{" {return lbrace} "}" {return rbrace}
    ( {return lparen} ) {return rparen}
    = - + - , - : - * - > - | - . {return [list $tok]}
    "-" {
      if {$tok eq "-" || $tok eq "->"} {return [list $tok]}
      return [list literal [new_obj int $tok]]
    }
    b {
      if {[string index $tok 1] eq "'"} {
	return [list literal [new_obj bytearray [string range $tok 2 end-1]]]
      }
      return [list ident $tok]
    }
    ' - {"} {# " Work around Emacs's confusion
      return [list literal [new_obj string [string range $tok 1 end-1]]]
    }
    < {return [list literal [new_obj enum [string range $tok 1 end-1]]]}
    / {return [list literal [new_obj name [rex {^[\w-]+} identifier in]]]}
    % {return [list enum [rex {^[a-zA-Z_]\w*} identifier in]]}
    & {return [list ref [rex {^[a-zA-Z_]\w*} identifier in]]}
    $ - @ {
      if {[cursor index $in] eq "\{"} {
        return [list [tree get {$ type_eval @ val_eval} $c] [brace_string in]]
      } else {
	cursor incr in -1
	return [list [tree get {$ type_var @ val_var} $c] [string range [parse_var_name in] 1 end]]
      }
    }
    default {
      if {[regex::match {^[a-zA-Z_]} $tok]} {return [list ident $tok]}
      if {[regex::match {^[0-9]} $tok]} {return [list literal [new_obj int $tok]]}
      fail "first char of parsed token not handled: '$c'" in
    }
  }
}
defp tok {tok} {prog1 [set t [get_token in]] {if {[lindex $t 0] ne $tok} {expected $tok in}}}
defp tok_val {tok} {lindex [tok $tok in] 1}
defp ident {} {tok_val ident in}
defp keyword {k} {if {[ident in] eq $k} {return $k} else {expected $k in}}
defp literal {} {types::parse_literal in}
defp str {} {
  set v [tok_val literal in]
  if {[type $v] ne "string"} {expected string in}
  return [subst -nocommands -novariables [val $v]]
}
defp int {} {
  set v [tok_val literal in]
  if {[type $v] ne "int"} {expected int in}
  return [val $v]
}
defp comma_sep {p} {repsep $p {tok ,} in}
defp fcomma_sep {p} {lflatten [comma_sep $p in]}
defp paren {p} {seq [list - {tok lparen} sel $p - {tok rparen}] in}
defp brace {p} {seq [list - {tok lbrace} sel $p - {tok rbrace}] in}
defp bracket {p} {seq [list - {tok lbracket} sel $p - {tok rbracket}] in}

defp alt_expr {} {
  set ls [rep1sep cat_expr {cat {ws {char "|"}}} in]
  if {[llength $ls] == 1} {return [lindex $ls 0]}
  return [list alt $ls]
}
defp cat_expr {} {
  set ls [rep postfix_expr in]
  if {[llength $ls] == 1} {return [lindex $ls 0]}
  return [list cat $ls]
}
defp atomic_expr {} {
  # Parse atomic expression
  ws in
  switch [cursor index $in] {
    $ {cursor incr in; list ref [rex {^\*|[a-zA-Z_]\w*} "var name" in]}
    % { # named tokens
      cursor incr in; set name [rex {^[a-zA-Z_]\w*} "token name" in]
      if {[get_ctx]} {return [namespace inscope $ctx(ns) {*}$ctx(perc) $name]}
      return [list tok $name]
    }
    "\[" {seq {- {char "\["} sel {rep postfix_expr} - ws - {char "\]"}} in}
    "\{" {list code [brace_string in]}
    "'" {do_squote [str in]}
    "\"" {subst [string range [rex {^\"[^\"]*\"} "string" in] 1 end-1]}
    "(" {seq {- {char "("} sel alt_expr - ws - {char ")"}} in}
    "~" { # seq
      cat {{char "~"} ws {char "\("}} in
      prog1 [list seq [flat {rep {seq {
	ign ws
	- {>> {alt {{char "@,^"} {ret ""}}} {tree getor {@ inl , ign ^ sel} $x -}}
	- postfix_expr
      }}} in]] {cat {ws {char "\)"}} in}
    }
    q {alt {{seq {- {char q} sel brace_string}} named_expr} in}
    s {
      alt {{>> {seq {- {char s} sel brace_string}} {
	if {[string length $x] == 1} {list char $x} else {list exact $x}
      }} named_expr} in
    }
    r {
      alt {{>> {seq {- {char r} sel brace_string}}
	{list rex "^(?:$x)" $x}} named_expr} in
    }
    c {
      alt {{>> {seq {ign {exact case} - {paren alt_expr}
	- {commit {brace {rep {seq {- {rep1sep {alt {str ident}} {tok -}}
	  ign {tok ->} - {paren alt_expr}}}}}}}} {
	    lassign $x det clauses
	    set res ""
	    foreach clause $clauses {
	      lassign $clause labels expr
	      foreach l $labels {tree set res $l $expr}
	    }
	    return [list predict $det $res]
	  }
      } named_expr} in
    }
    l {
      alt {{>> {seq {ign {exact lmatch} - {paren alt_expr}
	- {commit {brace {rep {seq {
	  - {rep1sep {paren {rep {alt {str ident}}}} {tok -}}
	  ign {tok ->} - {paren alt_expr}
	}}}}}}} {
	  lassign $x det clauses
	  set res ""
	  foreach clause $clauses {
	    lassign $clause pats expr
	    foreach pat $pats {
	      tree set res [lindex $pat 0] [list [lrange $pat 1 end] $expr]
	    }
	  }
	  return [list _lmatch $det $res]
	}
      } named_expr} in
    }
    _ {cursor incr in; return predval}
    default {return [named_expr in]}
  }
}
defp named_expr {} {
  set name [rex {^[a-zA-Z]\w*(?:::[a-zA-Z]\w*)*} identifier in]
  if {[string first :: $name] == -1 && [get_ctx]
      && [treeset contains $ctx(names) $name]} {return $ctx(ns)::$name}
  return $name
}

defp postfix_expr {} {
  set expr [atomic_expr in]
  while 1 {
    ws in
    switch [cursor index $in] {
      * {set expr [list rep $expr]; cursor incr in}
      + {set expr [list rep1 $expr]; cursor incr in}
      ? {set expr [list opt $expr]; cursor incr in}
      "\{" {
	switch [cursor range $in [cursor move $in 3]] {
	  "{*}" {set expr [list flat [list rep $expr]]}
	  "{+}" {set expr [list flat [list rep1 $expr]]}
	  default break
	}
	cursor incr in 3
      }
      : {
	if {[regex::match -cursor {^:(\w+)} $in -> name]} {
	  set expr [list name [cursor range {*}$name] $expr]
	  set in [lindex $name 1]
	} else break
      }
      default break
    }
  }
  foreach postfix [rep {seq {
    - ws
    sel {predict peekchar {
      > {seq {- {exact >>} ign ws - {commit brace_string}}}
      = {seq {- {char =} ign ws - {commit brace_string}}}
    }}
  }} in] {
    set expr [list [lindex $postfix 0] $expr [lindex $postfix 1]]
  }
  return $expr
}

proc do_squote {name} {
  if {[get_ctx] && [info exists ctx(squote)]} {
    return [namespace inscope $ctx(ns) {*}$ctx(squote) $name]
  }
  return [list [expr {[regex::match {^[a-zA-Z_]} $name] ? "keyword" : "tok"}] $name]
}

proc compile_parser {str} {
  set in [list $str 0]
  return [top {seq {sel alt_expr - ws - eof} in}]
}

# Entry points
proc top {script} {
  try {
    vars let deflvl -1 {return [uplevel 1 $script]}
  } trap {PARSE ERROR} {res d} - trap {PARSE FAIL} {res d} {
    lassign $res in msg
    error "parse failed at [cursor pos $in] ([cursor consume in 12]...)\n[dict get $d -errorinfo]"
  }
}

proc parse_string {parser str} {
  set in [list $str 0]
  return [top {prog1 [exp $parser in] {eof in}}]
}

proc parse_string/end {parser str} {
  set in [list $str 0]
  return [top {with_new_ctx {prog1 [exp $parser in] {ws in; eof in}}}]
}

proc get_ctx {} {
  if {[set l [vars get deflvl -1]] == -1} {return 0}
  uplevel 1 [list upvar $l ctx ctx]
  return 1
}

proc with_new_ctx {script} {
  upvar 1 ctx ctx
  set ctx(names) ""
  set ctx(perc) {list tok}
  vars let deflvl "#[expr {[info level]-1}]" {uplevel 1 $script}
}

proc load {info fun args} {
  with_new_ctx {
    lassign $info vals defs
    array set ctx $vals
    foreach x $defs {
      lmatch $x {
	{def name params body} {
          set in [list $body 0]
          set p [seq {sel alt_expr - ws - eof} in]
          if {[llength $params] > 0} {
            defcmd $ctx(ns)::$name apply {{params p args} {
              set in_var [lpop args]
              upvar 1 $in_var in
              set ls {}
              foreach param $params arg $args {lappend ls $param $arg}
              vars let {*}$ls {{*}$p in}
            } ::parse} $params $p
          } else {
            defcmd $ctx(ns)::$name ::parse::do $p
          }
	}
	{fun name params body} {defp $ctx(ns)::$name $params $body}
      }
    }
  }
  tailcall $ctx(ns)::$fun {*}$args
}

proc def {desc args} {
  set ctx(ns) [uplevel 1 {namespace current}]
  set ctx(names) ""
  foreach x [set defs [parse_string/end {
    (~('fun' ident ,ws brace_string ,ws brace_string)
     | ~([ret "def"] ident ([paren [comma_sep ident]]|{}) ,ws brace_string)
     | ~('-' ident ,ws brace_string))+
  } $desc]] {
    lmatch $x {
      {def name} - {fun name} {treeset set ctx(names) $name}
      {- opt val} {set ctx($opt) $val}
    }
  }
  set info [list [array get ctx] $defs]
  treeset for n $ctx(names) {uplevel 1 [list defcmd $n ::parse::load $info $n]}
}
