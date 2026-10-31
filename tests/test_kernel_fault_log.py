#!/usr/bin/env python3
"""Regression cases for the precommit serial fault oracle."""

import unittest

from check_kernel_fault_log import unexpected_faults


def log(*lines: str) -> str:
    return "\n".join(lines) + "\n"


PRE = (
    "[pre-report-terminal] tag=0x8000 index=0 process=0x0 "
    "thread=0xabc reason=unhandled_thread_fault subcode=2"
)
ARM_PRE = PRE.replace("subcode=2", "subcode=0")
X86_FAULT = "[UNHANDLED] thread_fault thread=0xabc subcode=2 payload=0x1"
ARM_FAULT = "[UNHANDLED] thread_fault thread=0xabc subcode=0 payload=0x1"
PASS = "[runner] PASS breakpoint_fault_01"


class FaultLogTests(unittest.TestCase):
    def test_proved_breakpoint_fault_on_both_architectures(self) -> None:
        self.assertEqual(unexpected_faults(log(PRE, X86_FAULT, PASS), "breakpoint_x86"), [])
        self.assertEqual(unexpected_faults(log(ARM_PRE, ARM_FAULT, PASS), "breakpoint_arm"), [])
        # The raw printer may interleave with another core; the structured
        # terminal record still supplies tag, thread, reason, and subcode.
        self.assertEqual(unexpected_faults(log(PRE, PASS), "breakpoint_x86"), [])
        self.assertEqual(unexpected_faults(log(ARM_PRE, PASS), "breakpoint_arm"), [])

    def test_other_contexts_and_faults_still_block(self) -> None:
        samples = (
            (log(PRE, X86_FAULT, PASS), "none"),
            (log(PRE, ARM_FAULT, PASS), "breakpoint_x86"),
            (log(PRE, X86_FAULT), "breakpoint_x86"),
            (log(PASS, PRE, X86_FAULT), "breakpoint_x86"),
            (log(PRE, X86_FAULT, PASS, X86_FAULT), "breakpoint_x86"),
            (log(PRE.replace("thread=0xabc", "thread=0xdef"), X86_FAULT, PASS), "breakpoint_x86"),
            (log(PRE.replace("index=0", "index=1"), X86_FAULT, PASS), "breakpoint_x86"),
            (log(PRE.replace("tag=0x8000", "tag=0x8001"), X86_FAULT, PASS), "breakpoint_x86"),
            (log(PRE.replace("subcode=2", "subcode=1"), X86_FAULT, PASS), "breakpoint_x86"),
            (log(PRE.replace(" subcode=2", ""), X86_FAULT, PASS), "breakpoint_x86"),
            (log(PRE, ARM_FAULT, PASS), "breakpoint_x86"),
            (log(PRE, X86_FAULT, PASS, "KERNEL PANIC: page fault"), "breakpoint_x86"),
        )
        for body, mode in samples:
            with self.subTest(mode=mode, body=body):
                self.assertTrue(unexpected_faults(body, mode))

    def test_pass_must_be_in_same_run(self) -> None:
        body = log(
            "[runner] === run 1/2 ===", PRE, X86_FAULT,
            "[runner] === run 2/2 ===", PASS,
        )
        self.assertTrue(unexpected_faults(body, "breakpoint_x86"))


if __name__ == "__main__":
    unittest.main()
