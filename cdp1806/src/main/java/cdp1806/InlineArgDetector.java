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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/**
 * Recovers a subroutine's inline-argument signature by walking its control flow from the entry
 * point and tracking how far R3 has advanced by the time it returns.
 *
 * <p>On entry R3 points at the inline argument bytes, and {@code SRET R3} resumes execution at
 * whatever R3 points at by then, so the net advance of R3 is exactly the number of argument
 * bytes consumed. Which instruction did the consuming gives the width: {@code LDA R3} and
 * {@code INC R3} take a byte, as do {@code LDXA}, {@code IRX} and {@code OUT} while X == 3;
 * {@code RLXA Rn} while X == 3 takes a 16-bit word.
 *
 * <p>A wrong answer is far worse than no answer, because the caller rewrites the listing from
 * it. So the walk reports a reason and declines whenever it cannot stay certain. Those cases are
 * what the override file is for.
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
	public static final int X_UNKNOWN = -1;

	/** What a walk established about a subroutine. */
	public static class CalleeInfo {
		/** The inline arguments it consumes. */
		public final InlineArgSpec spec;
		/**
		 * X as it stands when the subroutine returns, or {@link #X_UNKNOWN}. SCAL and SRET do
		 * not save or restore X, so a caller has to know what the callee left behind.
		 */
		public final int exitX;

		public CalleeInfo(InlineArgSpec spec, int exitX) {
			this.spec = spec;
			this.exitX = exitX;
		}
	}

	/** The outcome of a walk: either a signature, or the reason there isn't one. */
	public static class Result {
		/** The recovered signature, or null if it could not be determined. */
		public final InlineArgSpec spec;
		/** Why no signature was recovered, or null if one was. */
		public final String reason;
		/** X on return; meaningful only when {@link #spec} is non-null. */
		public final int exitX;

		private Result(InlineArgSpec spec, String reason, int exitX) {
			this.spec = spec;
			this.reason = reason;
			this.exitX = exitX;
		}

		public boolean isResolved() {
			return spec != null;
		}
	}

	private final Program program;
	private final Function<Address, CalleeInfo> calleeResolver;
	private final Function<Address, InlineArgSpec> siteResolver;

	/**
	 * @param calleeResolver looks up what is already known about a nested call target, returning
	 *            null when it is not yet known
	 * @param siteResolver looks up a signature pinned to one particular call site, by the
	 *            address of the SCAL instruction; returns null when there isn't one
	 */
	public InlineArgDetector(Program program, Function<Address, CalleeInfo> calleeResolver,
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

	/** What a path had established when it last reached a given (address, X) pair. */
	private static class Visit {
		final int delta;
		final String layout;

		Visit(int delta, String layout) {
			this.delta = delta;
			this.layout = layout;
		}
	}

	/**
	 * The subroutine a SCAL calls.
	 *
	 * <p>The operand is checked first and deliberately. Reference bookkeeping is not a
	 * dependable source here: SCAL targets are sometimes recorded as plain READ references
	 * rather than calls, and once the analyzer sets a fall-through override Ghidra adds a
	 * FALL_THROUGH reference that getFlows() then reports -- which would hand back the address
	 * execution resumes at instead of the subroutine being called. The operand encodes the
	 * target in the instruction itself and is unaffected by any of that.
	 *
	 * @return the call target, or null if it cannot be determined
	 */
	public static Address callTarget(Instruction in) {
		if (in.getNumOperands() > 1) {
			for (Object o : in.getOpObjects(1)) {
				if (o instanceof Address) {
					return (Address) o;
				}
				if (o instanceof Scalar) {
					try {
						return in.getAddress().getNewAddress(((Scalar) o).getUnsignedValue());
					}
					catch (RuntimeException e) {
						return null; // outside this address space
					}
				}
			}
		}
		Address fallThrough = in.getFallThrough();
		if (in.getFlowType().isCall()) {
			for (Address flow : in.getFlows()) {
				if (!flow.equals(fallThrough)) {
					return flow;
				}
			}
		}
		Address only = null;
		for (Reference r : in.getReferencesFrom()) {
			if (!r.getToAddress().isMemoryAddress() ||
				r.getReferenceType() == RefType.FALL_THROUGH) {
				continue;
			}
			if (only != null && !only.equals(r.getToAddress())) {
				return null; // ambiguous
			}
			only = r.getToAddress();
		}
		return only;
	}

	/**
	 * The register a SCAL passes its arguments through -- R(N) of {@code SCAL Rn,target}.
	 *
	 * @return the register, or null if the operand cannot be read
	 */
	public static Register argRegister(Instruction in) {
		return in.getNumOperands() > 0 ? in.getRegister(0) : null;
	}

	/** True for {@code SCAL R3,...}, the only form this analyzer understands. */
	public static boolean isR3Call(Instruction in) {
		return isR3(argRegister(in));
	}

	private static boolean isR3(Register r) {
		return r != null && "R3".equals(r.getName());
	}

	private static Result fail(String reason) {
		return new Result(null, reason, X_UNKNOWN);
	}

	/**
	 * @return the detected signature, or null if it could not be determined with confidence
	 */
	public InlineArgSpec detect(Address entry) {
		Result r = detectWithReason(entry);
		return r.spec;
	}

	/**
	 * Walks the subroutine, and where the walk had to guess at an unknown X, walks it a second
	 * time with the opposite guess. The answer is only accepted if both agree, so an X we cannot
	 * pin down costs us an answer only when it actually changes one.
	 */
	public Result detectWithReason(Address entry) {
		Walk first = new Walk(false);
		Result a = first.run(entry);
		if (!a.isResolved() || !first.guessedAtX) {
			return a;
		}
		Result b = new Walk(true).run(entry);
		if (!b.isResolved()) {
			return fail("X could not be determined after RET/DIS/MARK, and assuming X == 3 " +
				"gives a different outcome: " + b.reason);
		}
		if (!a.spec.toString().equals(b.spec.toString())) {
			return fail("depends on an X we cannot determine (" + a.spec + " if X is not 3, " +
				b.spec + " if it is)");
		}
		return new Result(a.spec, null, a.exitX == b.exitX ? a.exitX : X_UNKNOWN);
	}

	/** One pass over the subroutine under a fixed assumption about any unknown X. */
	private class Walk {

		private final boolean unknownXIsThree;
		/** Set when an unknown X actually had to be resolved by that assumption. */
		boolean guessedAtX;

		Walk(boolean unknownXIsThree) {
			this.unknownXIsThree = unknownXIsThree;
		}

		/** Resolves X for an instruction that addresses memory through R(X). */
		private int effectiveX(int x) {
			if (x != X_UNKNOWN) {
				return x;
			}
			guessedAtX = true;
			return unknownXIsThree ? 3 : ENTRY_X;
		}

		Result run(Address entry) {
			Listing listing = program.getListing();
			Deque<State> work = new ArrayDeque<>();
			// Keyed on address *and* X: reaching the same instruction with a different X is
			// normal (SEX is common inside loops) and has to be re-walked, because X decides
			// whether the R(X) instructions move R3.
			Map<String, Visit> seen = new HashMap<>();
			work.push(new State(entry, 0, ENTRY_X, new ArrayList<>()));

			InlineArgSpec result = null;
			int exitX = Integer.MIN_VALUE;
			boolean layoutAmbiguous = false;
			int steps = 0;

			while (!work.isEmpty()) {
				if (++steps > MAX_STEPS) {
					return fail("control flow too large to follow");
				}
				State s = work.pop();

				String key = s.addr + "/" + s.x;
				String layout = new InlineArgSpec(s.args).toString();
				Visit prev = seen.get(key);
				if (prev != null) {
					if (prev.delta != s.r3delta) {
						return fail("R3 differs between paths reaching " + s.addr);
					}
					if (!prev.layout.equals(layout)) {
						// Same number of bytes read, carved up differently. The skip distance
						// is unaffected, but we no longer know the widths, so the answer is
						// degraded to plain bytes rather than picking whichever path won.
						layoutAmbiguous = true;
					}
					continue;
				}
				seen.put(key, new Visit(s.r3delta, layout));

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
							return fail(
								"return paths disagree (" + result + " vs " + candidate + ")");
						}
						result = candidate;
						exitX = exitX == Integer.MIN_VALUE || exitX == x ? x : X_UNKNOWN;
						continue; // terminator: nothing flows out of it
					}
					case "SEP": {
						// SEP Rn sets P = n, so control leaves here and does not fall through.
						// With R3 that is exactly the return SRET performs. With any other
						// register it is a jump, and we only continue if we can see where to:
						// the immediately preceding RLDI names the destination in the reboot
						// idiom (RLDI R0,0x0000 then SEP R0). Otherwise we cannot rule out that
						// the destination consumes further arguments and returns, so decline.
						Register target = in.getRegister(0);
						if (isR3(target)) {
							if (delta < 0) {
								return fail(
									"R3 moved backwards by " + (-delta) + " at " + s.addr);
							}
							InlineArgSpec candidate = reconcile(args, delta);
							if (result != null &&
								!result.toString().equals(candidate.toString())) {
								return fail("return paths disagree (" + result + " vs " +
									candidate + ")");
							}
							result = candidate;
							exitX = exitX == Integer.MIN_VALUE || exitX == x ? x : X_UNKNOWN;
							continue;
						}
						Address jump = precedingRldiValue(in, target);
						if (jump == null) {
							return fail("SEP " + target + " at " + s.addr +
								" jumps somewhere we cannot follow");
						}
						if (program.getMemory().contains(jump)) {
							work.push(new State(jump, delta, x, args));
						}
						continue;
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
					case "DBNZ": {
						// Decrements the register and loops. R3 as a loop counter is not a
						// return pointer any more, so there is nothing sound to report.
						if (isR3(in.getRegister(0))) {
							return fail("R3 used as a DBNZ counter at " + s.addr);
						}
						break;
					}
					case "RLXA": {
						// Reads two bytes through R(X) into the operand register, advancing
						// R(X) by two. If the destination is R3 the return pointer is gone.
						if (isR3(in.getRegister(0))) {
							return fail("R3 overwritten by RLXA at " + s.addr);
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
					case "DSAV": {
						// R(X) - 1 three times over, saving T, D and D shifted.
						if (effectiveX(x) == 3) {
							delta -= 3;
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
						if (effectiveX(x) == 3) {
							return fail("RNX would overwrite R3 at " + s.addr);
						}
						break;
					}
					case "SCAL": {
						// A nested SCAL saves and restores the register it passes arguments
						// through, so with R3 the caller's R3 is unchanged -- but we still have
						// to step over the nested call's own inline arguments, and SCAL does
						// not restore X, so X becomes whatever the callee left.
						if (!isR3Call(in)) {
							return fail("nested " + in + " at " + s.addr +
								" passes arguments through a register other than R3");
						}
						Address nestedTarget = callTarget(in);
						if (nestedTarget == null) {
							return fail("indeterminate call target at " + s.addr);
						}
						InlineArgSpec nested = siteResolver.apply(in.getAddress());
						int nestedExitX = X_UNKNOWN;
						if (nested == null) {
							CalleeInfo info = calleeResolver.apply(nestedTarget);
							if (info != null) {
								nested = info.spec;
								nestedExitX = info.exitX;
							}
						}
						if (nested == null) {
							return fail("nested call to " + nestedTarget +
								" has no known signature yet");
						}
						Address after = in.getMaxAddress().next();
						if (after == null) {
							return fail("call at the very end of memory, " + s.addr);
						}
						try {
							fallThrough = nested.isEmpty() ? after : after.add(nested.byteCount());
						}
						catch (RuntimeException e) {
							return fail("arguments run past the end of memory at " + s.addr);
						}
						x = nestedExitX;
						break;
					}
					case "RET":
					case "DIS":
					case "MARK": {
						// These reload X -- from M(R(X)), or from P for MARK -- and RET/DIS also
						// advance the old R(X) by one, which matters only if that was R3.
						if (effectiveX(x) == 3) {
							delta += 1;
							args.add(InlineArgSpec.Kind.BYTE);
						}
						x = X_UNKNOWN;
						break;
					}
					default: {
						// Anything not modelled above must at least be shown not to touch R3.
						// SLEIGH tells us what each instruction writes, so use it rather than
						// assuming an unfamiliar opcode is harmless.
						for (Object o : in.getResultObjects()) {
							if (o instanceof Register && isR3((Register) o)) {
								return fail(m + " at " + s.addr + " writes R3");
							}
						}
						break;
					}
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
				return fail("no return to R3 reached from " + entry);
			}
			if (layoutAmbiguous && !result.isEmpty()) {
				result = flatten(result.byteCount());
			}
			return new Result(result, null, exitX == Integer.MIN_VALUE ? X_UNKNOWN : exitX);
		}
	}

	/**
	 * The address an immediately preceding {@code RLDI Rn,imm} loaded into {@code reg}, or null
	 * if the previous instruction is not such a load.
	 */
	private Address precedingRldiValue(Instruction in, Register reg) {
		Instruction prev = in.getPrevious();
		if (prev == null || !"RLDI".equals(prev.getMnemonicString())) {
			return null;
		}
		Register loaded = prev.getRegister(0);
		if (loaded == null || reg == null || !loaded.getName().equals(reg.getName())) {
			return null;
		}
		Scalar sc = prev.getScalar(1);
		if (sc == null) {
			return null;
		}
		try {
			return in.getAddress().getNewAddress(sc.getUnsignedValue());
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * Cross-checks the widths we attributed against the net R3 advance. They disagree when R3
	 * moved in a way that was counted but not classified -- {@code DEC R3}, or an R(X) store
	 * while X is 3 -- in which case the widths are no longer trustworthy and the answer is
	 * degraded to a flat run of bytes covering the same distance.
	 */
	private InlineArgSpec reconcile(List<InlineArgSpec.Kind> args, int delta) {
		InlineArgSpec spec = new InlineArgSpec(args);
		if (spec.byteCount() == delta) {
			return spec;
		}
		return delta == 0 ? InlineArgSpec.NONE : flatten(delta);
	}

	private static InlineArgSpec flatten(int bytes) {
		List<InlineArgSpec.Kind> flat = new ArrayList<>();
		for (int i = 0; i < bytes; i++) {
			flat.add(InlineArgSpec.Kind.BYTE);
		}
		return new InlineArgSpec(flat);
	}
}
