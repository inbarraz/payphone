package cdp1806;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

/**
 * Recovers a subroutine's inline-argument signature by walking its control flow from the entry
 * point and tracking how far R3 has advanced by the time {@code SRET R3} returns.
 *
 * <p>On entry R3 points at the inline argument bytes, and {@code SRET R3} resumes execution at
 * whatever R3 points at by then, so the net advance of R3 is exactly the number of argument
 * bytes consumed. Which instruction did the consuming tells us the width: {@code LDA R3} takes a
 * byte, {@code RLXA Rn} while X == 3 takes a 16-bit word.
 *
 * <p>The walk reports a reason and gives up rather than guessing whenever it cannot stay
 * certain. Those cases are what the override file is for.
 */
public class InlineArgDetector {

	/** Safety valve for pathological control flow. */
	private static final int MAX_STEPS = 20000;

	/**
	 * X at subroutine entry. SCAL pushes the caller's R(N) through R(X), so R(X) is necessarily
	 * the stack register at every call site; in this firmware that is R2, which is also what
	 * MARK hardcodes.
	 */
	private static final int ENTRY_X = 2;

	/** X holds this when we cannot tell what it contains. */
	private static final int X_UNKNOWN = -1;

	/** The outcome of a walk: either a signature, or the reason there isn't one. */
	public static class Result {
		/** The recovered signature, or null if it could not be determined. */
		public final InlineArgSpec spec;
		/** Why no signature was recovered, or null if one was. */
		public final String reason;

		private Result(InlineArgSpec spec, String reason) {
			this.spec = spec;
			this.reason = reason;
		}

		public boolean isResolved() {
			return spec != null;
		}
	}

	private final Program program;
	private final Function<Address, InlineArgSpec> calleeResolver;
	private final Function<Address, InlineArgSpec> siteResolver;

	/**
	 * @param calleeResolver looks up an already-known signature for a nested call target,
	 *            returning null when it is not yet known
	 * @param siteResolver looks up a signature pinned to one particular call site, by the
	 *            address of the SCAL instruction; returns null when there isn't one
	 */
	public InlineArgDetector(Program program, Function<Address, InlineArgSpec> calleeResolver,
			Function<Address, InlineArgSpec> siteResolver) {
		this.program = program;
		this.calleeResolver = calleeResolver;
		this.siteResolver = siteResolver;
	}

	private static class State {
		final Address addr;
		final int r3delta;
		final int x;
		final List<InlineArgSpec.Kind> args;

		State(Address addr, int r3delta, int x, List<InlineArgSpec.Kind> args) {
			this.addr = addr;
			this.r3delta = r3delta;
			this.x = x;
			this.args = args;
		}
	}

	/**
	 * The subroutine a SCAL calls.
	 *
	 * <p>Not simply {@code getFlows()}: that only reports flow-type references, and in a
	 * database built over several Ghidra versions some SCAL targets are recorded as plain READ
	 * references instead of calls, which would leave those call sites invisible. The operand
	 * names the target either way, so it is the more dependable source.
	 *
	 * @return the call target, or null if it cannot be determined
	 */
	public static Address callTarget(Instruction in) {
		if (in.getFlowType().isCall()) {
			Address[] flows = in.getFlows();
			if (flows.length == 1) {
				return flows[0];
			}
		}
		if (in.getNumOperands() > 1) {
			for (Object o : in.getOpObjects(1)) {
				if (o instanceof Address) {
					return (Address) o;
				}
				if (o instanceof Scalar) {
					return in.getAddress().getNewAddress(((Scalar) o).getUnsignedValue());
				}
			}
		}
		Address only = null;
		for (Reference r : in.getReferencesFrom()) {
			if (!r.getToAddress().isMemoryAddress()) {
				continue;
			}
			if (only != null && !only.equals(r.getToAddress())) {
				return null; // ambiguous
			}
			only = r.getToAddress();
		}
		return only;
	}

	private static boolean isR3(Register r) {
		return r != null && "R3".equals(r.getName());
	}

	private static Result fail(String reason) {
		return new Result(null, reason);
	}

	/**
	 * @return the detected signature, or null if it could not be determined with confidence
	 */
	public InlineArgSpec detect(Address entry) {
		return detectWithReason(entry).spec;
	}

	public Result detectWithReason(Address entry) {
		Listing listing = program.getListing();
		Deque<State> work = new ArrayDeque<>();
		// Keyed on address *and* X: reaching the same instruction with a different X is normal
		// (SEX is common inside loops) and has to be re-walked, because X decides whether the
		// R(X) instructions move R3. Reaching it with a different R3 is what we cannot resolve.
		Map<String, Integer> seen = new HashMap<>();
		work.push(new State(entry, 0, ENTRY_X, new ArrayList<>()));

		InlineArgSpec result = null;
		int steps = 0;

		while (!work.isEmpty()) {
			if (++steps > MAX_STEPS) {
				return fail("control flow too large to follow");
			}
			State s = work.pop();

			String key = s.addr + "/" + s.x;
			Integer prevDelta = seen.get(key);
			if (prevDelta != null) {
				if (prevDelta == s.r3delta) {
					continue;
				}
				return fail("R3 differs between paths reaching " + s.addr);
			}
			seen.put(key, s.r3delta);

			Instruction in = listing.getInstructionAt(s.addr);
			if (in == null) {
				return fail("no instruction at " + s.addr + " (not disassembled?)");
			}

			String m = in.getMnemonicString();
			int delta = s.r3delta;
			int x = s.x;
			List<InlineArgSpec.Kind> args = new ArrayList<>(s.args);
			Address fallThrough = in.getFallThrough();

			switch (m) {
				case "SRET": {
					if (!isR3(in.getRegister(0))) {
						return fail("returns through " + in.getRegister(0) + " at " + s.addr);
					}
					if (delta < 0) {
						return fail("R3 moved backwards by " + (-delta) + " at " + s.addr);
					}
					InlineArgSpec candidate = reconcile(args, delta);
					if (result != null && !result.toString().equals(candidate.toString())) {
						return fail("return paths disagree (" + result + " vs " + candidate + ")");
					}
					result = candidate;
					continue; // terminator: nothing flows out of it
				}
				case "SEX": {
					Scalar sc = in.getScalar(0);
					if (sc == null) {
						return fail("unreadable SEX operand at " + s.addr);
					}
					x = (int) sc.getUnsignedValue();
					break;
				}
				case "LDA":
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
				case "RLXA": {
					if (x == X_UNKNOWN) {
						return fail("X unknown at RLXA, " + s.addr);
					}
					if (x == 3) {
						delta += 2;
						args.add(InlineArgSpec.Kind.WORD);
					}
					break;
				}
				case "IRX":
				case "LDXA":
				case "OUT": {
					if (x == X_UNKNOWN) {
						return fail("X unknown at " + m + ", " + s.addr);
					}
					if (x == 3) {
						delta += 1;
						args.add(InlineArgSpec.Kind.BYTE);
					}
					break;
				}
				case "STXD": {
					if (x == X_UNKNOWN) {
						return fail("X unknown at STXD, " + s.addr);
					}
					if (x == 3) {
						delta -= 1;
					}
					break;
				}
				case "RSXD": {
					if (x == X_UNKNOWN) {
						return fail("X unknown at RSXD, " + s.addr);
					}
					if (x == 3) {
						delta -= 2;
					}
					break;
				}
				case "RLDI":
				case "PLO":
				case "PHI": {
					if (isR3(in.getRegister(0))) {
						return fail("R3 reloaded by " + m + " at " + s.addr);
					}
					break;
				}
				case "RNX": {
					if (x == X_UNKNOWN || x == 3) {
						return fail("RNX would overwrite R3 at " + s.addr);
					}
					break;
				}
				case "SCAL": {
					// A nested SCAL saves and restores R3, so the caller's R3 is unchanged --
					// but we still have to step over the nested call's own inline arguments.
					Address nestedTarget = callTarget(in);
					if (nestedTarget == null) {
						return fail("indeterminate call target at " + s.addr);
					}
					Address resumeAt = scalFallThrough(in, nestedTarget);
					if (resumeAt == null) {
						return fail("nested call to " + nestedTarget + " has no known signature yet");
					}
					fallThrough = resumeAt;
					break;
				}
				case "RET":
				case "DIS":
				case "MARK": {
					// These reload X (from M(R(X)), or from P for MARK). R3 is untouched, so the
					// walk continues -- but X is now unknown, and any later R(X) instruction
					// will stop it.
					x = X_UNKNOWN;
					break;
				}
				case "SEP": {
					return fail("SEP at " + s.addr + " changes which register is the PC");
				}
				default:
					break;
			}

			// Branch targets continue this subroutine; a call target does not. Following a
			// call would walk into the callee and come back with the callee's own argument
			// count attributed to this one.
			if (!in.getFlowType().isCall()) {
				for (Address flow : in.getFlows()) {
					if (program.getMemory().contains(flow)) {
						work.push(new State(flow, delta, x, args));
					}
				}
			}
			if (fallThrough != null && program.getMemory().contains(fallThrough)) {
				work.push(new State(fallThrough, delta, x, args));
			}
		}

		if (result == null) {
			return fail("no SRET R3 reached from " + entry);
		}
		return new Result(result, null);
	}

	/**
	 * Cross-checks the widths we attributed against the net R3 advance. If they disagree, some
	 * R3 movement happened that we did not classify, so fall back to a flat run of bytes.
	 */
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

	/** Where control actually resumes after a nested SCAL, or null if we cannot tell. */
	private Address scalFallThrough(Instruction in, Address target) {
		if (in.isFallThroughOverridden()) {
			return in.getFallThrough(); // an earlier pass already worked this one out
		}
		// A signature pinned to this exact call site wins: the callee may be variadic, taking a
		// different number of bytes depending on how it was called.
		InlineArgSpec nested = siteResolver.apply(in.getAddress());
		if (nested == null) {
			nested = calleeResolver.apply(target);
		}
		if (nested == null) {
			return null;
		}
		Address after = in.getMaxAddress().next();
		if (after == null) {
			return null;
		}
		return nested.isEmpty() ? after : after.add(nested.byteCount());
	}
}
