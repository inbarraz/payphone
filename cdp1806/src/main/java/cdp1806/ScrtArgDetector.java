package cdp1806;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
		/** The extra inline arguments, or null when undetermined. */
		public final InlineArgSpec spec;
		/** Why it could not be determined, or null. */
		public final String reason;

		private Result(InlineArgSpec spec, String reason) {
			this.spec = spec;
			this.reason = reason;
		}

		public boolean isResolved() {
			return spec != null;
		}

		/** Extra inline bytes, or -1 when undetermined. */
		public int extraBytes() {
			return spec == null ? -1 : spec.byteCount();
		}
	}

	private final Program program;
	private final String callReg;
	private final String returnReg;
	/** Extra bytes already known for a nested callee, or null if not yet known. */
	private final Function<Address, InlineArgSpec> known;

	public ScrtArgDetector(Program program, String callReg, String returnReg,
			Function<Address, InlineArgSpec> known) {
		this.program = program;
		this.callReg = callReg;
		this.returnReg = returnReg;
		this.known = known;
	}

	private static Result fail(String reason) {
		return new Result(null, reason);
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
		if (!ra.spec.toString().equals(rb.spec.toString())) {
			return fail("depends on an X we cannot determine (" + ra.spec +
				" if X is not 3, " + rb.spec + " if it is)");
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
			// Addresses whose LDA R3 has already been counted as the low half of a word.
			Set<Address> consumed = new HashSet<>();
			work.push(new Object[] { entry, 0, X_UNKNOWN, new ArrayList<InlineArgSpec.Kind>() });

			InlineArgSpec result = null;
			int steps = 0;

			while (!work.isEmpty()) {
				if (++steps > MAX_STEPS) {
					return fail("control flow too large to follow");
				}
				Object[] s = work.pop();
				Address addr = (Address) s[0];
				int delta = (Integer) s[1];
				int x = (Integer) s[2];
				@SuppressWarnings("unchecked")
				List<InlineArgSpec.Kind> args =
					new ArrayList<>((List<InlineArgSpec.Kind>) s[3]);

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
							InlineArgSpec candidate = reconcile(args, delta);
							if (result != null &&
								!result.toString().equals(candidate.toString())) {
								return fail("return paths disagree (" + result + " vs " +
									candidate + ")");
							}
							result = candidate;
							continue;
						}
						if (isReg(r, callReg)) {
							// A nested call: one byte of SEP, two of address, plus whatever
							// that callee reads for itself. R3 is saved and restored across it.
							Address t = targetOf(in);
							if (t == null) {
								return fail("indeterminate nested call target at " + addr);
							}
							InlineArgSpec extra = known.apply(t);
							if (extra == null) {
								return fail("nested call to " + t + " has no known size yet");
							}
							try {
								fallThrough = addr.add(3 + extra.byteCount());
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
					case "LDA": {
						if (isR3(in.getRegister(0))) {
							if (consumed.contains(addr)) {
								// Already counted as the low half of a word pair.
								delta += 1;
							}
							else {
								Address low = wordPairLowHalf(in);
								if (low != null) {
									// LDA R3 / PHI Rn / LDA R3 / PLO Rn builds a 16-bit value
									// out of two byte reads; report it as the word it is.
									consumed.add(low);
									delta += 1;
									args.add(InlineArgSpec.Kind.WORD);
								}
								else {
									delta += 1;
									args.add(InlineArgSpec.Kind.BYTE);
								}
							}
						}
						break;
					}
					case "INC": {
						if (isR3(in.getRegister(0))) {
							delta += 1;
							args.add(InlineArgSpec.Kind.BYTE);
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
							args.add(InlineArgSpec.Kind.WORD);
						}
						break;
					}
					case "IRX":
					case "LDXA":
					case "OUT": {
						if (effectiveX(x) == 3) {
							delta += 1;
							args.add(InlineArgSpec.Kind.BYTE);
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
							args.add(InlineArgSpec.Kind.BYTE);
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
							work.push(new Object[] { flow, delta, x, args });
						}
					}
				}
				if (fallThrough != null && program.getMemory().contains(fallThrough)) {
					work.push(new Object[] { fallThrough, delta, x, args });
				}
			}

			if (result == null) {
				return fail("no SEP " + returnReg + " reached from " + entry);
			}
			return new Result(result, null);
		}
	}

	/**
	 * Recognises {@code LDA R3 / PHI Rn / LDA R3 / PLO Rn} (either half first), which reads two
	 * bytes to build one 16-bit value. Pure byte counting would call that two arguments.
	 *
	 * @return the address of the second LDA R3, so it is not counted twice, or null
	 */
	private Address wordPairLowHalf(Instruction first) {
		Instruction i2 = first.getNext();
		Instruction i3 = i2 == null ? null : i2.getNext();
		Instruction i4 = i3 == null ? null : i3.getNext();
		if (i2 == null || i3 == null || i4 == null) {
			return null;
		}
		String m2 = i2.getMnemonicString();
		String m4 = i4.getMnemonicString();
		boolean halves = ("PHI".equals(m2) && "PLO".equals(m4)) ||
			("PLO".equals(m2) && "PHI".equals(m4));
		if (!halves || !"LDA".equals(i3.getMnemonicString()) || !isR3(i3.getRegister(0))) {
			return null;
		}
		Register a = i2.getRegister(0);
		Register b = i4.getRegister(0);
		if (a == null || b == null || !a.getName().equals(b.getName()) || isR3(a)) {
			return null;
		}
		return i3.getAddress();
	}

	/** Falls back to a flat run of bytes when the widths do not account for the whole advance. */
	private InlineArgSpec reconcile(List<InlineArgSpec.Kind> args, int delta) {
		InlineArgSpec spec = new InlineArgSpec(args);
		if (spec.byteCount() == delta) {
			return spec;
		}
		if (delta == 0) {
			return InlineArgSpec.NONE;
		}
		List<InlineArgSpec.Kind> flat = new ArrayList<>();
		for (int i = 0; i < delta; i++) {
			flat.add(InlineArgSpec.Kind.BYTE);
		}
		return new InlineArgSpec(flat);
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
