package cdp1806;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

/**
 * Works out how many <em>extra</em> inline bytes a SCRT subroutine consumes, beyond the two that
 * the call routine itself reads as the target address.
 *
 * <p>By the time a callee is entered, {@code SCRT_CALL} has already done its two {@code LDA R3},
 * so R3 points just past the address. Anything further the callee reads through R3 is an argument
 * of its own, and {@code SEP} of the return register resumes execution at wherever R3 has reached.
 * So the net advance of R3 between entry and the return is exactly the number of extra bytes.
 *
 * <pre>
 * 2422: LDA R3     &lt;- one extra byte
 * 2423: PLO RF
 * 2424: LDI 00
 * 2426: STR RF
 * 2427: SEP R5     &lt;- returns past it
 * </pre>
 *
 * <p>X is not known on entry: the call routine leaves behind whatever it last selected, and that
 * differs between SCRT implementations. Rather than assume, a subroutine whose result depends on
 * X is walked twice, once with X taken to be 3 and once not, and an answer is only returned when
 * both agree. The walk declines, with a reason, on anything else it cannot model — a wrong count
 * puts the listing out of phase, which is worse than leaving a call unmarked.
 */
public class ScrtArgDetector {

	// SCRT subroutines are small; a walk that needs more than this is not one we can
	// usefully describe anyway, and the detector runs over every callee repeatedly.
	private static final int MAX_STEPS = 6000;
	private static final int X_UNKNOWN = -1;

	public static class Result {
		/** Extra inline bytes, or -1 when undetermined. */
		public final int extraBytes;
		/** Why it could not be determined, or null. */
		public final String reason;

		private Result(int extraBytes, String reason) {
			this.extraBytes = extraBytes;
			this.reason = reason;
		}

		public boolean isResolved() {
			return extraBytes >= 0;
		}
	}

	private final Program program;
	private final String callReg;
	private final String returnReg;
	/** Extra bytes already known for a nested callee, or null if not yet known. */
	private final Function<Address, Integer> known;

	public ScrtArgDetector(Program program, String callReg, String returnReg,
			Function<Address, Integer> known) {
		this.program = program;
		this.callReg = callReg;
		this.returnReg = returnReg;
		this.known = known;
	}

	private static Result fail(String reason) {
		return new Result(-1, reason);
	}

	private static boolean isReg(Register r, String name) {
		return r != null && name != null && name.equals(r.getName());
	}

	private static boolean isR3(Register r) {
		return isReg(r, "R3");
	}

	public Result detect(Address entry) {
		Walk a = new Walk(false);
		Result ra = a.run(entry);
		if (!ra.isResolved() || !a.guessedAtX) {
			return ra;
		}
		Result rb = new Walk(true).run(entry);
		if (!rb.isResolved()) {
			return fail("depends on an X we cannot determine: " + rb.reason);
		}
		if (ra.extraBytes != rb.extraBytes) {
			return fail("depends on an X we cannot determine (" + ra.extraBytes +
				" if X is not 3, " + rb.extraBytes + " if it is)");
		}
		return ra;
	}

	private class Walk {
		private final boolean unknownXIsThree;
		boolean guessedAtX;

		Walk(boolean unknownXIsThree) {
			this.unknownXIsThree = unknownXIsThree;
		}

		private int effectiveX(int x) {
			if (x != X_UNKNOWN) {
				return x;
			}
			guessedAtX = true;
			return unknownXIsThree ? 3 : 2;
		}

		Result run(Address entry) {
			Listing listing = program.getListing();
			Deque<Object[]> work = new ArrayDeque<>();
			Map<String, Integer> seen = new HashMap<>();
			work.push(new Object[] { entry, 0, X_UNKNOWN });

			int result = Integer.MIN_VALUE;
			int steps = 0;

			while (!work.isEmpty()) {
				if (++steps > MAX_STEPS) {
					return fail("control flow too large to follow");
				}
				Object[] s = work.pop();
				Address addr = (Address) s[0];
				int delta = (Integer) s[1];
				int x = (Integer) s[2];

				String key = addr + "/" + x;
				Integer prev = seen.get(key);
				if (prev != null) {
					if (prev == delta) {
						continue;
					}
					return fail("R3 differs between paths reaching " + addr);
				}
				seen.put(key, delta);

				Instruction in = listing.getInstructionAt(addr);
				if (in == null) {
					return fail("no instruction at " + addr + " (not disassembled?)");
				}

				String m = in.getMnemonicString();
				Address fallThrough = in.getFallThrough();

				switch (m) {
					case "SEP": {
						Register r = in.getRegister(0);
						if (isReg(r, returnReg)) {
							if (delta < 0) {
								return fail("R3 moved backwards by " + (-delta) + " at " + addr);
							}
							if (result != Integer.MIN_VALUE && result != delta) {
								return fail("return paths disagree (" + result + " vs " +
									delta + " extra byte(s))");
							}
							result = delta;
							continue;
						}
						if (isReg(r, callReg)) {
							// A nested call: one byte of SEP, two of address, plus whatever
							// that callee reads for itself. R3 is saved and restored across it.
							Address t = targetOf(in);
							if (t == null) {
								return fail("indeterminate nested call target at " + addr);
							}
							Integer extra = known.apply(t);
							if (extra == null) {
								return fail("nested call to " + t + " has no known size yet");
							}
							try {
								fallThrough = addr.add(3 + extra);
							}
							catch (RuntimeException e) {
								return fail("nested call runs past the end of memory at " + addr);
							}
							// The call routine leaves X as it pleases.
							x = X_UNKNOWN;
							break;
						}
						return fail("SEP " + r + " at " + addr + " is neither call nor return");
					}
					case "SEX": {
						Scalar sc = in.getScalar(0);
						if (sc == null) {
							return fail("unreadable SEX operand at " + addr);
						}
						x = (int) sc.getUnsignedValue();
						break;
					}
					case "LDA":
					case "INC": {
						if (isR3(in.getRegister(0))) {
							delta += 1;
						}
						break;
					}
					case "DEC": {
						if (isR3(in.getRegister(0))) {
							delta -= 1;
						}
						break;
					}
					case "DBNZ": {
						if (isR3(in.getRegister(0))) {
							return fail("R3 used as a DBNZ counter at " + addr);
						}
						break;
					}
					case "RLXA": {
						if (isR3(in.getRegister(0))) {
							return fail("R3 overwritten by RLXA at " + addr);
						}
						if (effectiveX(x) == 3) {
							delta += 2;
						}
						break;
					}
					case "IRX":
					case "LDXA":
					case "OUT": {
						if (effectiveX(x) == 3) {
							delta += 1;
						}
						break;
					}
					case "STXD": {
						if (effectiveX(x) == 3) {
							delta -= 1;
						}
						break;
					}
					case "RSXD": {
						if (effectiveX(x) == 3) {
							delta -= 2;
						}
						break;
					}
					case "RLDI":
					case "PLO":
					case "PHI": {
						if (isR3(in.getRegister(0))) {
							return fail("R3 reloaded by " + m + " at " + addr);
						}
						break;
					}
					case "RET":
					case "DIS":
					case "MARK": {
						if (effectiveX(x) == 3) {
							delta += 1;
						}
						x = X_UNKNOWN;
						break;
					}
					default: {
						for (Object o : in.getResultObjects()) {
							if (o instanceof Register && isR3((Register) o)) {
								return fail(m + " at " + addr + " writes R3");
							}
						}
						break;
					}
				}

				if (!in.getFlowType().isCall()) {
					for (Address flow : in.getFlows()) {
						if (program.getMemory().contains(flow)) {
							work.push(new Object[] { flow, delta, x });
						}
					}
				}
				if (fallThrough != null && program.getMemory().contains(fallThrough)) {
					work.push(new Object[] { fallThrough, delta, x });
				}
			}

			if (result == Integer.MIN_VALUE) {
				return fail("no SEP " + returnReg + " reached from " + entry);
			}
			return new Result(result, null);
		}
	}

	/** The two bytes after a SEP call, read big-endian, or null if they are not a valid address. */
	Address targetOf(Instruction in) {
		try {
			Address at = in.getAddress().add(1);
			int hi = program.getMemory().getByte(at) & 0xFF;
			int lo = program.getMemory().getByte(at.add(1)) & 0xFF;
			Address t = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(((hi << 8) | lo) & 0xFFFF);
			return program.getMemory().contains(t) ? t : null;
		}
		catch (Exception e) {
			return null;
		}
	}
}
