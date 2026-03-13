"""Binary protections detector - checks Mach-O security flags."""

from __future__ import annotations

from typing import TYPE_CHECKING

from macholib.MachO import MachO

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# Mach-O header flag constants. Defined here as fallbacks in case
# the installed macholib version doesn't export them by name.
try:
    from macholib.mach_o import MH_PIE
except ImportError:
    MH_PIE = 0x200000

try:
    from macholib.mach_o import MH_NO_HEAP_EXECUTION
except ImportError:
    MH_NO_HEAP_EXECUTION = 0x1000000

try:
    from macholib.mach_o import MH_ALLOW_STACK_EXECUTION
except ImportError:
    MH_ALLOW_STACK_EXECUTION = 0x20000


class BinaryProtectionsDetector(BaseDetector):
    """Checks Mach-O binary security flags (PIE, stack/heap execution)."""

    name = "binary_protections"
    description = "Checks Mach-O binary for security-relevant compilation flags"
    owasp_category = "M4"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Analyze binary for missing security protections.

        Args:
            context: Analysis context with binary_path set.

        Returns:
            List of findings for missing protections.
        """
        findings: list[Finding] = []
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        try:
            macho = MachO(str(context.binary_path))
        except (ValueError, OSError) as e:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Unable to parse Mach-O binary",
                    description=(
                        f"Could not parse the main binary. It may be encrypted "
                        f"(FairPlay DRM) or not a valid Mach-O file: {e}"
                    ),
                    location=location,
                    evidence=str(e),
                    owasp="M4 - Insufficient Input/Output Validation",
                    remediation=(
                        "Decrypt the binary before analysis (e.g., using a jailbroken device)"
                    ),
                    cwe_id=119,
                )
            )
            return findings

        # Check the first architecture header.
        # NOTE: FAT/universal binaries may have multiple headers; for MVP we check the first.
        header = macho.headers[0]
        flags = header.header.flags

        if not (flags & MH_PIE):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Binary not compiled as Position Independent Executable (PIE)",
                    description=(
                        "The binary does not have the PIE flag set. PIE enables ASLR "
                        "(Address Space Layout Randomization), which makes memory-based "
                        "exploits significantly harder."
                    ),
                    location=location,
                    evidence=f"Mach-O flags: 0x{flags:08x} (MH_PIE not set)",
                    owasp="M4 - Insufficient Input/Output Validation",
                    remediation="Compile with -fPIE flag and link with -pie",
                    cwe_id=119,
                )
            )

        if not (flags & MH_NO_HEAP_EXECUTION):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title="Heap execution not disabled",
                    description=(
                        "The binary does not have the MH_NO_HEAP_EXECUTION flag set. "
                        "This means the heap memory region is executable, which could "
                        "be leveraged in exploitation."
                    ),
                    location=location,
                    evidence=f"Mach-O flags: 0x{flags:08x} (MH_NO_HEAP_EXECUTION not set)",
                    owasp="M4 - Insufficient Input/Output Validation",
                    remediation="Enable non-executable heap in compiler/linker settings",
                    cwe_id=119,
                )
            )

        if flags & MH_ALLOW_STACK_EXECUTION:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Stack execution is allowed",
                    description=(
                        "The binary has MH_ALLOW_STACK_EXECUTION set, meaning stack "
                        "memory is executable. This is a classic exploitation vector "
                        "for stack-based buffer overflows."
                    ),
                    location=location,
                    evidence=f"Mach-O flags: 0x{flags:08x} (MH_ALLOW_STACK_EXECUTION set)",
                    owasp="M4 - Insufficient Input/Output Validation",
                    remediation="Remove the -allow_stack_execution linker flag",
                    cwe_id=119,
                )
            )

        return findings
