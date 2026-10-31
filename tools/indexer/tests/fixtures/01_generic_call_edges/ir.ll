; Hand-cut pre-optimization IR in exactly the shape `zig build -Demit_ir`
; produces for the fixture sources: the monomorphized generic is a *quoted*
; LLVM global whose name embeds the instantiation argument list and carries
; a `__anon_NNNN` discriminator for the comptime callback parameter.
ModuleID = 'BitcodeBuffer'

define internal fastcc void @source.fire() unnamed_addr #1 !dbg !1 {
  call fastcc void @source.dispatch(), !dbg !10
  ret void
}

define internal fastcc void @source.dispatch() unnamed_addr #1 !dbg !2 {
  call fastcc void @source.propagateAndWake(), !dbg !11
  ret void
}

define internal fastcc void @source.propagateAndWake() unnamed_addr #1 !dbg !3 {
  call fastcc void @"slab.SecureSlab(source.Ctx,256).forEachAlive__anon_1234"(ptr nonnull @source.instance), !dbg !12
  ret void
}

define internal fastcc void @"slab.SecureSlab(source.Ctx,256).forEachAlive__anon_1234"(ptr nonnull %0) unnamed_addr #1 !dbg !4 {
  call fastcc i1 @source.visitor(ptr %0, ptr %0), !dbg !13
  ret void
}

define internal fastcc i1 @source.visitor(ptr %0, ptr %1) unnamed_addr #1 !dbg !5 {
  call fastcc void @source.wake(), !dbg !14
  ret i1 true
}

define internal fastcc void @source.wake() unnamed_addr #1 !dbg !6 {
  ret void
}

; A second instantiation of the same generic collapses onto the same
; declaration entity — proving the merge is by generic decl, not by
; monomorphization.
define internal fastcc ptr @"slab.SecureSlab(source.Ctx,512).create"(ptr nonnull %0) unnamed_addr #1 !dbg !7 {
  ret ptr %0
}

!10 = !DILocation(line: 12, column: 5, scope: !1)
!11 = !DILocation(line: 16, column: 5, scope: !2)
!12 = !DILocation(line: 20, column: 14, scope: !3)
!13 = !DILocation(line: 13, column: 18, scope: !4)
!14 = !DILocation(line: 24, column: 5, scope: !5)
