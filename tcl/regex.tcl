eval_in ::regex

# Requires: util, parse, tcl_parser (for backslash).
namespace import ::parse::defp
# Compilation-related variabels
variable capture_count 0
variable next_label 0
variable blocks {}
variable forward {}
variable pos {}
variable reverse_pos {}
variable buf {}
variable insts {chr goto split save any end start match bracket}

defp parse_cat {} {fold cat [parse::rep regex::parse_quantified in]}
defp parse_exp {} {fold alt [parse::repsep regex::parse_cat {char "|"} in]}
defp parse_greedy {} {parse::alt {{= {char "?"} 0} {ret 1}} in}
defp parse_primary {} {
  variable capture_count
  switch [cursor index $in] {
    "\(" {
      cursor incr in
      if {[parse::alt {{= {exact "?:"} 0} {ret 1}} in]} {
	# Reporting
	set n [incr capture_count]
	set exp [list sub [parse_exp in] $n]
      } else {
	# Non-reporting
	set exp [parse_exp in]
      }
      parse::char "\)" in
      return $exp
    }
    . {cursor incr in; return any}
    ^ {cursor incr in; return start}
    $ {cursor incr in; return end}
    "\[" {
      cursor incr in
      set invert 0
      if {[cursor index $in] eq "^"} {cursor incr in; set invert 1}
      set ls [parse::rep regex::parse_bracket_elt in]
      parse::char "\]" in
      if {[llength $ls] == 0} {return empty}
      return [list bracket $invert [join $ls ""]]
    }
    "\{" {
      cursor incr in
      if {[string is digit [cursor index $in]]} {
	parse::fail "quantifier operand invalid" in
      }
      return [list chr "\{"]
    }
    "\\" {return [parse_backslash 0 in]}
    | {parse::fail "" in}
    "\)" {parse::fail "parentheses unbalanced" in}
    "" {parse::expected "regular expression" in}
    default {return [list chr [cursor consume in 1]]}
  }
}
defp parse_backslash {in_bracket} {
  set range {
    cursor incr in 2
    if {$in_bracket} {return $r}
    return [list bracket 0 $r]
  }
  switch [cursor index [cursor move $in 1]] {
    d {set r 0-9; eval $range}
    s {set r " \r\n\t\v"; eval $range}
    w {set r {a-zA-Z0-9_}; eval $range}
    A {cursor incr in 2; return [lindex {start A} $in_bracket]}
    Z {cursor incr in 2; return [lindex {end Z} $in_bracket]}
    "" {cursor incr in; return "\\"}
    default {
      set c [parse_backslash_escape in]
      if {$in_bracket} {return $c}
      return [list chr $c]
    }
  }
}
defp parse_backslash_escape {} {
  parse::char "\\" in
  set c [cursor index $in]
  foreach v [tree get* {a \x7 b \x8 f \xc n \xa r \xd t \x9 v \xb} $c] {
    cursor incr in; return $v
  }
  foreach digits [tree get* {x 2 u 4 U 8} $c] {
    cursor incr in
    set res 0
    for {set i 0} {$i < $digits} {incr i} {
      if {[string is xdigit [set d [cursor index $in]]]} {
        cursor incr in; set res [expr {$res*16+[scan $d %x]}]
      } else {
        break
      }
    }
    if {$i > 0} {return [format %c $res]} else {return $c}
  }
  if {[cursor eof $in]} {return "\\"}
  return [cursor consume in 1]
}
defp parse_bracket_elt {} {
  switch [cursor index $in] {
    "\]"    {parse::fail "done" in}
    ""      {parse::err "bracket unbalanced" in}
    "\\"    {parse_backslash 1 in}
    default {return [cursor consume in 1]}
  }
}
defp parse_int {} {
  if {[cursor index $in] eq "0"} {cursor incr in; return 0}
  set res ""
  while {[string is digit -strict [cursor index $in]]} {append res [cursor consume in 1]}
  if {$res eq ""} {parse::expected "integer" in}
  return $res
}
defp parse_quantified {} {
  set exp [parse_primary in]
  # Possibly parse a modifier
  if {[lindex $exp 0] ni {start end}} {
    switch [cursor index $in] {
      + {cursor incr in; set exp [list rep1 $exp [parse_greedy in]]}
      * {cursor incr in; set exp [list rep $exp [parse_greedy in]]}
      ? {cursor incr in; set exp [list alt $exp empty [parse_greedy in]]}
      "\{" {
	# Simplify counted expressions by expansion
	lassign [parse::seq {
	  ign {char "\{"} - regex::parse_int
	  - {opt {cat {{char ","} {opt regex::parse_int}}}}
	  ign {char "\}"} - regex::parse_greedy
	} in] lo hi greedy
	set min [fold cat [lmap x [iota $lo] {id $exp}]]
	if {[llength $hi] == 0} {
	  set exp $min
	} elseif {[llength [lindex $hi 0 1]] == 0} {
	  set exp [list cat $min [list rep $exp $greedy]]
	} elseif {[set hi [lindex $hi 0 1 0]] < $lo} {
	  parse::err "bad range \[$lo, $hi\]" in
	} else {
	  set tail [list alt $exp empty $greedy]
	  for {set i $lo} {$i+1 < $hi} {incr i} {
	    set tail [list alt [list cat $tail $exp] empty $greedy]
	  }
	  set exp [list cat $min $tail]
	}
      }
    }
  }
  return $exp
}

proc dbg {msg} {debug [uplevel 1 [list subst $msg]]}
proc dbg {msg} {}

proc fold {op ls} {
  if {[llength $ls] == 0} {return empty}
  set exp [lindex $ls 0]
  foreach x [lrange $ls 1 end] {set exp [list $op $exp $x]}
  return $exp
}

proc compile {str {print 0}} {
  variable forward
  variable pos
  variable reverse_pos
  variable blocks
  variable next_label
  variable buf
  variable capture_count

  # Parse regex
  set capture_count 0
  set in [list $str 0]
  set ast [parse::top {parse::seq {sel regex::parse_exp - eof} in}]
  dbg {parsed $ast}

  # Check if anchored by ^ or \A
  set first $ast
  while {[lindex $first 0] eq "cat"} {set first [lindex $first 1]}
  set anchored [expr {[lindex $first 0] eq "start"}] 

  # Add implicit capture of entire match and implicit ".*?" at
  # beginning of regex.
  set ast [list sub $ast 0]
  if {!$anchored}  {set ast [list cat {rep any 0} $ast]}

  # Compile/linearize regex.
  set blocks {Lm match}
  set next_label 0
  set start_exp [comp $ast {goto Lm}]
  dbg {start_exp $start_exp, blocks $blocks}

  # Find all blocks of the form "L1: goto L2" and forward L1 to L2
  set forward {}
  tree for {label exp} $blocks {
    if {[lindex $exp 0] eq "goto"} {
      tree set forward $label [lindex $exp 1]
      tree unset blocks $label; # don't generate code for the forwarded goto
    }
  }
  if {[tree size $forward] > 0} {dbg {forward is $forward}}

  # Path-compress the forwarding table
  tree for {from to} $forward {
    set queue {}
    while {[llength [set next [tree get* forward $to]]] == 1} {
      lappend queue $to
      set to [lindex $next 0]
    }
    if {[llength $queue] > 0} {
      tree set forward $from $to
      foreach l $queue {tree set forward $l $to}
    }
  }

  # Schedule the blocks: try to put goto target following the goto and
  # remove the goto.
  set traces {}
  set label Ls
  set exp $start_exp
  while 1 {
    # Try to extend the block (which will possibly no longer be a
    # "basic" block)
    set trace {}
    while 1 {
      # Find the last instruction of the block (and record our path to
      # it starting from the expression).
      set last $exp
      set indices {}
      while {[lindex $last 0] ni {match goto split}} {
        lappend indices [expr {[llength $last]-1}]
        set last [lindex $last end]
      }

      # Check if last instruction is a goto to a block that has yet to
      # be placed.
      if {[lindex $last 0] ne "goto"} break
      set target [tree getor $forward [lindex $last 1] [lindex $last 1]]
      if {[llength [set r [tree get* $blocks $target]]] == 0} break

      # If that is the case, add the block to our current trace. Note
      # that we wrap the target in a "label" expression because it can
      # be the target of a goto form elsewhere.
      lappend trace [list $exp $indices]
      set exp [list label $target [lindex $r 0]]

      # Remove the absorbed block
      tree unset blocks $target
      dbg {merged and removed $target}
    }

    # Fold the trace together using the calculated indices
    foreach x [lreverse $trace[set trace ""]] {
      lassign $x parent indices
      lset parent $indices $exp
      set exp $parent
    }

    # Add the whole trace and choose a new (arbitrary) starting point.
    lappend traces [list label $label $exp]
    if {[tree size $blocks] == 0} break
    tree for {label exp} $blocks break
    tree unset blocks $label
  }

  dbg {traces is $traces}
  set buf {}
  set pos {}
  foreach b $traces {asm $b}; # pass 1
  set reverse_pos {}
  if {$print} {
    # Prepare PC->label map for disassembly
    tree for {label offset} $pos {tree set reverse_pos $offset $label}
  }
  set buf {}
  foreach b $traces {asm $b $print}; # pass 2
  return $buf
}

# CPS-transform regex
proc comp {ex k} {
  variable blocks
  lassign $ex h a b
  switch $h {
    empty {return $k}
    chr - any - bracket - start - end {lappend ex $k}
    sub {list save [expr {$b*2}] [comp $a [list save [expr {$b*2+1}] $k]]}
    cat {comp $a [comp $b $k]}
    alt {
      set k [list goto [labelof $k]]
      split [comp $a $k] [comp $b $k] [lindex $ex 3]
    }
    rep {
      # Micro-optimization: Russ Cox's version loops back to the
      # split, we just duplicate the split.
      gen_label L g
      set test [split $g $k $b]
      tree set blocks $L [comp $a $test]
      return $test
    }
    rep1 {
      gen_label L g
      set ret [list label $L [comp $a [split $g $k $b]]]
    }
    default {error "unhandled $h"}
  }
}

proc labelof {k} {
  variable blocks
  if {[lindex $k 0] eq "goto"} {return [lindex $k 1]}
  if {[lindex $k 0] eq "match"} {return Lm}
  gen_label L g
  tree set blocks $L $k
  return $L
}

proc split {l r greedy} {
  if {$greedy ne "" && $greedy == 0} {set t $l; set l $r; set r $t}
  return [list split [labelof $l] [labelof $r]]
}

proc gen_label {label goto} {
  variable next_label
  set g [list goto [set l L[incr next_label]]]
  uplevel 1 [list set $label $l]
  uplevel 1 [list set $goto $g]
}

proc asm {ex {print 0}} {
  variable buf
  variable pos
  variable reverse_pos
  set op [lindex $ex 0]
  
  if {$print && $op ne "label"} {
    puts -nonewline [format "%-4s%5d " \
                         [tree getor $reverse_pos [string length $buf] ""] [string length $buf]]
    puts [lrange $ex 0 \
              [expr {[llength $ex]-1-([lindex $ex 0] ni {goto split match})}]]
  }
    
  switch $op {
    any - start - end - match {emit_op $op}
    chr {emit_op chr; emit [encoding convertto utf-8 [lindex $ex 1]]}
    save {emit_op save; emit [binary format S [lindex $ex 1]]}
    goto {emit_op goto; emit_addr [lindex $ex 1]}
    split {emit_op split; emit_addr [lindex $ex 1]; emit_addr [lindex $ex 2]}
    label {tree set pos [lindex $ex 1] [string length $buf]}
    bracket {asm_bracket [lindex $ex 1] [lindex $ex 2]}
    default {error "unhandled op $op"}
  }
  if {$op ni {match goto split}} {asm [lindex $ex end] $print}
}

proc asm_bracket {invert chars} {
  variable buf
  set ascii 1

  set in [list $chars 0]
  set ls [parse::top {parse::rep1 {seq {
    - anychar inl {opt {seq {- {char "-"} sel anychar}}}
  }} in}]

  # Combine chars and ranges into only ranges.
  set ranges {}
  foreach x $ls {
    set lo [scan [lindex $x 0] %c]
    if {$lo > 127} {set ascii 0}
    set hi $lo
    if {[llength $x] == 2} {
      set hi [scan [lindex $x 1] %c]
      if {$hi > 127} {set ascii 0}
      if {$hi < $lo} {set hi $lo}
    }
    lappend ranges $lo $hi
  }

  # Sort and merge ranges. Note: empty ranges already simplified away
  # by parser.
  set ranges [lsort -integer -stride 2 $ranges[set ranges ""]]
  set merged [list [lindex $ranges 0]]; # low value of first range
  set limit [lindex $ranges 1]; # high value of first range
  foreach {lo hi} [lrange $ranges 2 end] {
    if {$lo > $limit} {lappend merged $limit $lo}
    set limit $hi
  }
  lappend merged $limit
  dbg {merged ranges is $merged, ascii=$ascii}

  emit_op bracket [expr {($ascii << 1) | $invert}]
  emit [binary format S [expr {[llength $merged]/2}]]
  if {$ascii} {
    set f c
  } else {
    set f nu
    
    # Align code point array to 32-bit boundary.
    while {[string length $buf] & 3} {emit \0}
  }
  emit [binary format $f[llength $merged] $merged]
}

proc emit {code} {
  variable buf
  append buf [bytearray $code]
}

proc emit_op {o {flags 0}} {
  variable insts
  set n [lsearch -exact $insts $o]
  if {$n == -1} {error "no such op $o"}
  emit [binary format c [expr {$n<<2 | $flags}]]
}

proc emit_addr {label} {
  variable forward
  variable pos
  set target [tree getor $forward $label $label]
  emit [binary format S [tree getor $pos $target 0]]
}

proc print_enum {} {
  variable insts
  puts "/* Generated by print_enum in regex.tcl */"
  puts "enum inst {"
  puts [join [lmap i $insts {id "    INST_[string toupper $i]"}] ",\n"]
  puts "};"
}
