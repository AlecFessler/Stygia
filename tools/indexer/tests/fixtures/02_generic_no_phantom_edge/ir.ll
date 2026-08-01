; `array_list` is std, not part of the indexed tree, so `array_list.Aligned`
; names no entity. Erasing its instantiation would yield `array_list.append`
; — which also names no entity here, but the guard must reject the name on
; the *head* check so a tree that happens to contain a same-named module
; never acquires a phantom edge.
ModuleID = 'BitcodeBuffer'

define internal fastcc i64 @mod.caller() unnamed_addr #1 !dbg !1 {
  call fastcc i64 @"mod.logf__anon_9911"(i64 1), !dbg !10
  call fastcc i64 @"array_list.Aligned(mod.T,null).append"(ptr null), !dbg !11
  ret i64 0
}

define internal fastcc i64 @"mod.logf__anon_9911"(i64 %0) unnamed_addr #1 !dbg !2 {
  call fastcc i64 @mod.append(i64 %0), !dbg !12
  ret i64 0
}

define internal fastcc i64 @mod.append(i64 %0) unnamed_addr #1 !dbg !3 {
  ret i64 0
}

!10 = !DILocation(line: 16, column: 12, scope: !1)
!11 = !DILocation(line: 16, column: 12, scope: !1)
!12 = !DILocation(line: 12, column: 12, scope: !2)
