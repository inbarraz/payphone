package cdp1806;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Teaches Ghidra about calls made through the RCA Standard Call and Return Technique.
 *
 * <p>The CDP1802 has no call instruction. Software supplies one: a register — conventionally R4 —
 * is loaded with the address of a short routine, and {@code SEP R4} switches the program counter
 * to it. That routine reads the bytes immediately following the {@code SEP} out of the caller's
 * instruction stream, usually two of them forming the subroutine address, and enters the
 * subroutine. A matching {@code SEP R5} returns.
 *
 * <p>Ghidra sees none of this. {@code SEP} compiles to a computed jump with no resolvable target,
 * so no call is recorded and no call graph is built, and the inline bytes are disassembled as
 * instructions, which puts the listing out of phase.
 *
 * <p>This analyzer is told which register to treat as the call, and how many bytes follow it. It
 * is deliberately not enabled by default and does not try to deduce the convention: register
 * assignments differ between SCRT implementations, and applying the wrong one to a program that
 * does not use the technique would corrupt its listing.
 */
public class ScrtCallAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "CDP1802 SCRT calls (SEP Rn)";
	private static final String DESCRIPTION =
		"Treats SEP of a nominated register as a call that carries its target inline, correcting " +
			"the flow so the inline bytes are not disassembled as code and the call graph is " +
			"built. Off by default: it must be told which register the program uses.";

	private static final String OPT_CALL_REG = "Call register";
	private static final String OPT_CALL_REG_DESC =
		"Which SEP Rn is a call, for example R4. Leave blank to mark up returns only.";

	private static final String OPT_INLINE_BYTES = "Inline bytes after SEP";
	private static final String OPT_INLINE_BYTES_DESC =
		"How many bytes follow the SEP and belong to it. 2 is the callee address in the standard " +
			"technique. 0 means the SEP carries nothing and only its flow is corrected. More than " +
			"2 means the first two are the address and the rest are the callee's own arguments.";

	private static final String OPT_RETURN_REG = "Return register";
	private static final String OPT_RETURN_REG_DESC =
		"Which SEP Rn is a return, for example R5. Marking these lets Ghidra close function " +
			"bodies. Leave blank to skip.";

	private static final String OPT_CREATE_FUNCTIONS = "Create functions at call targets";
	private static final String OPT_CREATE_FUNCTIONS_DESC =
		"Create a function at each distinct address called through the call register.";

	private static final String PROCESSOR = "cdp1806";

	/** Marks a comment as this analyzer's own, so its markup can be recognised and undone. */
	private static final String COMMENT_PREFIX = "scrt ";

	/**
	 * Prefix of the repeatable comment placed on a callee that reads extra inline bytes. Ghidra
	 * echoes a repeatable comment at every site that references the address, so this shows up in
	 * the calling code, which is where the adjustment has to be made.
	 */
	private static final String CALLEE_NOTE_PREFIX = "SCRT callee: ";

	/**
	 * Marks a repeatable comment as one this analyzer wrote. A comment that begins with a
	 * readable signature is authoritative whatever it says next, so this only distinguishes our
	 * own earlier output from a human's prose.
	 */
	private static final String AUTO_MARKER = "[scrt auto]";

	/**
	 * Resolving callee sizes walks every callee, and analysis calls back many times as the
	 * listing grows. Redoing it when nothing has been disassembled since last time is pure cost,
	 * so the result is kept until the instruction count moves.
	 */
	/**
	 * What this session last wrote at each site. Re-marking a site with markup it has already
	 * been given means something is undoing it, and repeating would spin; re-marking it with
	 * *different* markup is a legitimate correction, usually a signature that has been edited.
	 */
	private final Map<Address, String> markedThisSession = new HashMap<>();
	private boolean hintsLogged;
	private int cachedAtInstructionCount = -1;
	private String cachedAtSignatures = "";
	private Map<Address, InlineArgSpec> cachedExtras;

	private String callRegOpt = "R4";
	private int inlineBytes = 2;
	private String returnRegOpt = "R5";
	private boolean createFunctions = true;

	public ScrtCallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		// Off by default on purpose. Which register means "call" is a property of the program,
		// and guessing wrong would rewrite a listing that was fine.
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PROCESSOR.equalsIgnoreCase(program.getLanguage().getProcessor().toString());
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_CALL_REG, OptionType.STRING_TYPE, "R4", null,
			OPT_CALL_REG_DESC);
		options.registerOption(OPT_INLINE_BYTES, 2, null, OPT_INLINE_BYTES_DESC);
		options.registerOption(OPT_RETURN_REG, OptionType.STRING_TYPE, "R5", null,
			OPT_RETURN_REG_DESC);
		options.registerOption(OPT_CREATE_FUNCTIONS, true, null, OPT_CREATE_FUNCTIONS_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		callRegOpt = options.getString(OPT_CALL_REG, "R4");
		inlineBytes = options.getInt(OPT_INLINE_BYTES, 2);
		returnRegOpt = options.getString(OPT_RETURN_REG, "R5");
		createFunctions = options.getBoolean(OPT_CREATE_FUNCTIONS, true);
	}

	/** Accepts R4, r4, 4 or 0x4, and returns the canonical register name, or null for blank. */
	private static String normaliseRegister(String text) {
		if (text == null) {
			return null;
		}
		String t = text.trim();
		if (t.isEmpty()) {
			return null;
		}
		if (t.toLowerCase().startsWith("0x")) {
			t = t.substring(2);
		}
		if (t.length() == 1 && Character.digit(t.charAt(0), 16) >= 0) {
			return "R" + Character.toUpperCase(t.charAt(0));
		}
		return t.toUpperCase();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		String callReg = normaliseRegister(callRegOpt);
		String returnReg = normaliseRegister(returnRegOpt);
		if (callReg == null && returnReg == null) {
			Msg.info(this, NAME + ": neither a call nor a return register is set; nothing to do.");
			return false;
		}
		if (inlineBytes < 0 || inlineBytes > 32) {
			log.appendMsg(NAME, "Inline byte count " + inlineBytes + " is out of range (0-32).");
			return false;
		}

		if (!hintsLogged) {
			hintsLogged = true;
			logVectorHints(program, monitor);
		}

		int changed = 0;
		Set<Address> targets = new TreeSet<>();
		AddressSet toDisassemble = new AddressSet();
		List<Instruction> seps = findSepInstructions(program, monitor);

		// What each callee reads for itself, on top of the address. Resolved before anything is
		// marked, because a site's extent depends on the callee it names.
		Map<Address, InlineArgSpec> extras =
			resolveExtras(program, seps, callReg, returnReg, monitor);

		for (Instruction in : seps) {
			monitor.checkCancelled();
			Register r = in.getRegister(0);
			String name = r == null ? null : r.getName();

			if (callReg != null && callReg.equals(name)) {
				Address t = readTarget(program, in);
				if (t != null) {
					targets.add(t);
				}
				InlineArgSpec extra = t == null ? null : extras.get(t);
				if (markCall(program, in, t, extra == null ? InlineArgSpec.NONE : extra,
					toDisassemble, log)) {
					changed++;
				}
			}
			else if (returnReg != null && returnReg.equals(name)) {
				if (markReturn(in)) {
					changed++;
				}
			}
			else if (ownsMarkup(in)) {
				// This site was marked under a previous option set and no longer qualifies.
				if (removeMarkup(program, in, log)) {
					changed++;
				}
			}
		}

		if (!toDisassemble.isEmpty()) {
			new DisassembleCommand(toDisassemble, null, true).applyTo(program, monitor);
		}

		int created = 0;
		if (createFunctions) {
			for (Address t : targets) {
				monitor.checkCancelled();
				if (program.getFunctionManager().getFunctionAt(t) == null &&
					program.getListing().getInstructionAt(t) != null) {
					CreateFunctionCmd cmd = new CreateFunctionCmd(null, t, null,
						SourceType.ANALYSIS, false, false);
					if (cmd.applyTo(program, monitor)) {
						created++;
					}
				}
			}
		}

		Msg.info(this, String.format(
			"%s: call register %s with %d inline byte(s), return register %s; " +
				"changed %d site(s), %d distinct target(s), %d function(s) created.",
			NAME, callReg == null ? "(none)" : callReg, inlineBytes,
			returnReg == null ? "(none)" : returnReg, changed, targets.size(), created));
		return changed > 0;
	}

	private List<Instruction> findSepInstructions(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<Instruction> result = new ArrayList<>();
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			if ("SEP".equals(in.getMnemonicString())) {
				result.add(in);
			}
		}
		return result;
	}

	// ---------------------------------------------------------------- call sites

	/**
	 * Marks one call site. Its extent is the configured base count plus whatever the callee reads
	 * for itself.
	 *
	 * @return true if anything changed
	 */
	private boolean markCall(Program program, Instruction in, Address target,
			InlineArgSpec extra, AddressSet toDisassemble, MessageLog log) {

		Listing listing = program.getListing();
		Address site = in.getAddress();
		int total = inlineBytes + extra.byteCount();
		Address resume;
		Address argStart = null;
		Address argEnd = null;
		try {
			resume = site.add(1 + total);
			if (total > 0) {
				argStart = site.add(1);
				argEnd = site.add(total);
			}
		}
		catch (RuntimeException e) {
			Msg.info(this, NAME + ": " + site + " - inline bytes run past the end of memory");
			return false;
		}

		if (argEnd != null) {
			String problem = validate(program, argStart, argEnd);
			if (problem != null) {
				Msg.info(this, NAME + ": " + site + " - " + problem + "; skipped");
				return false;
			}
		}

		String comment = COMMENT_PREFIX + "call" + (target == null ? "" : " -> " + target) +
			(extra.isEmpty() ? "" : " (" + upper(extra) + ")");
		if (isAlreadyCorrect(in, resume, comment, program, target, total)) {
			return false; // nothing to do; this is what stops the analyzer looping
		}
		if (comment.equals(markedThisSession.get(site))) {
			// Already given exactly this markup and it still does not read as correct, so
			// something is undoing it. Repeating would only spin. Say so once and leave it.
			Msg.info(this, NAME + ": " + site +
				" did not hold its markup; leaving it as is rather than re-applying");
			return false;
		}
		markedThisSession.put(site, comment);

		try {
			if (argStart != null) {
				clearOwnedReferences(program, argStart, argEnd);
				listing.clearCodeUnits(argStart, argEnd, false);
				Address at = argStart;
				if (inlineBytes >= 2) {
					// A pointer rather than a plain word: the bytes are an address, so typing
					// them as one makes the listing show the callee's name, makes the operand
					// navigable, and gives the callee a data reference of its own alongside the
					// call reference. A word is used only when the value is not a real address,
					// where calling it a pointer would be a lie.
					listing.createData(at, addressDataType(program, target));
					at = at.add(2);
				}
				// Any remaining bytes of the base count have no stated meaning.
				Address baseEnd = argStart.add(inlineBytes - 1);
				while (at.compareTo(baseEnd) <= 0) {
					listing.createData(at, (DataType) ByteDataType.dataType);
					at = at.add(1);
				}
				// The callee's own arguments, typed by what the signature says they are.
				for (InlineArgSpec.Kind kind : extra.kinds()) {
					if (kind == InlineArgSpec.Kind.BYTE) {
						listing.createData(at, (DataType) ByteDataType.dataType);
					}
					else {
						listing.createData(at, addressDataType(program, targetOf(program, at)));
					}
					at = at.add(kind.size);
				}
			}
			// Order matters. Changing the flow override re-derives the instruction's fall-through
			// and discards any override on it, so the flow has to be set first and the
			// fall-through second, or every pass finds the fall-through wrong and marks the site
			// again for ever.
			// BRANCHIND becomes CALLIND, so this reads as a call rather than a computed jump.
			in.setFlowOverride(FlowOverride.CALL);
			if (total > 0) {
				in.setFallThrough(resume);
			}
			if (target != null) {
				Reference ref = program.getReferenceManager()
						.addMemoryReference(site, target, RefType.UNCONDITIONAL_CALL,
							SourceType.ANALYSIS, ghidra.program.model.listing.CodeUnit.MNEMONIC);
				program.getReferenceManager().setPrimary(ref, true);
			}
			in.setComment(CommentType.EOL, comment);
			// Correcting the flow is what exposes the next instruction; without disassembling it
			// the listing cannot grow past this call on a later pass.
			scheduleDisassembly(listing, resume, toDisassemble);
			if (target != null) {
				scheduleDisassembly(listing, target, toDisassemble);
			}
			return true;
		}
		catch (Exception e) {
			log.appendMsg(NAME, "Could not mark up the call at " + site + ": " + e);
			return false;
		}
	}

	private boolean isAlreadyCorrect(Instruction in, Address resume, String comment,
			Program program, Address target, int total) {
		if (!comment.equals(in.getComment(CommentType.EOL))) {
			return false;
		}
		if (in.getFlowOverride() != FlowOverride.CALL) {
			return false;
		}
		if (total > 0 && !resume.equals(in.getFallThrough())) {
			return false;
		}
		if (target != null) {
			boolean found = false;
			for (Reference r : in.getReferencesFrom()) {
				if (r.getReferenceType().isCall() && target.equals(r.getToAddress())) {
					found = true;
				}
			}
			if (!found) {
				return false;
			}
			// Catches markup left by an earlier version that typed the address as a plain word.
			Data d = program.getListing().getDefinedDataAt(in.getAddress().add(1));
			if (d == null || !(d.getDataType() instanceof Pointer)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The type for the two address bytes: a two-byte pointer when they really do name a location
	 * in the program, and a plain word when they do not.
	 */
	private DataType addressDataType(Program program, Address target) {
		if (target == null) {
			return WordDataType.dataType;
		}
		DataType p = program.getDataTypeManager().getPointer(null, 2);
		return p != null ? p : (DataType) WordDataType.dataType;
	}

	/** The address a 16-bit argument holds, or null if it does not name one. */
	private Address targetOf(Program program, Address at) {
		try {
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

	/** Reads the big-endian 16-bit target, or null if it is not inside the program. */
	private Address readTarget(Program program, Instruction in) {
		if (inlineBytes < 2) {
			return null;
		}
		try {
			Address at = in.getAddress().add(1);
			int hi = program.getMemory().getByte(at) & 0xFF;
			int lo = program.getMemory().getByte(at.add(1)) & 0xFF;
			Address t = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(((hi << 8) | lo) & 0xFFFF);
			return program.getMemory().contains(t) ? t : null;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/**
	 * Works out, for every callee, how many bytes it reads beyond the address, repeating until
	 * nothing new is learned — a callee that itself makes a SCRT call can only be sized once that
	 * inner call's size is known. Callees that cannot be determined are reported and treated as
	 * taking none, which leaves their call sites marked as plain two-byte calls: a miss rather
	 * than a corruption.
	 */
	private Map<Address, InlineArgSpec> resolveExtras(Program program, List<Instruction> seps,
			String callReg, String returnReg, TaskMonitor monitor) throws CancelledException {

		long instructions = program.getListing().getNumInstructions();

		Map<Address, InlineArgSpec> known = new HashMap<>();
		if (callReg == null || returnReg == null || inlineBytes < 2) {
			cachedExtras = known;
			cachedAtInstructionCount = (int) instructions;
			return known;
		}
		Set<Address> targets = new TreeSet<>();
		for (Instruction in : seps) {
			monitor.checkCancelled();
			Register r = in.getRegister(0);
			if (r != null && callReg.equals(r.getName())) {
				Address t = readTarget(program, in);
				if (t != null) {
					targets.add(t);
				}
			}
		}

		// The cache has to notice a signature being edited, not just new instructions, or a
		// correction written by hand would not take effect until something else was disassembled.
		StringBuilder sig = new StringBuilder();
		for (Address t : targets) {
			monitor.checkCancelled();
			InlineArgSpec c = commentSignature(program, t);
			if (c != null) {
				sig.append(t).append('=').append(c).append(';');
			}
		}
		String signatures = sig.toString();
		if (cachedExtras != null && instructions == cachedAtInstructionCount &&
			signatures.equals(cachedAtSignatures)) {
			return cachedExtras;
		}
		cachedAtSignatures = signatures;

		// A signature written on the callee wins outright. It is the one place a human can
		// say what the arguments mean, and meaning is exactly what byte counting cannot see:
		// a 16-bit pointer read with two LDA R3 looks the same as two unrelated bytes.
		Set<Address> stated = new HashSet<>();
		for (Address t : targets) {
			monitor.checkCancelled();
			InlineArgSpec fromComment = commentSignature(program, t);
			if (fromComment != null) {
				known.put(t, fromComment);
				stated.add(t);
				Msg.info(this, NAME + ": callee " + t + " signature stated as " +
					upper(fromComment));
			}
		}

		ScrtArgDetector detector = new ScrtArgDetector(program, callReg, returnReg, known::get);
		boolean progress = true;
		while (progress) {
			monitor.checkCancelled();
			progress = false;
			for (Address t : targets) {
				if (known.containsKey(t)) {
					continue;
				}
				ScrtArgDetector.Result r = detector.detect(t);
				if (r.isResolved()) {
					known.put(t, r.spec);
					progress = true;
				}
			}
		}

		for (Address t : targets) {
			monitor.checkCancelled();
			if (stated.contains(t)) {
				// Never rewrite a stated signature, but do say so when detection disagrees:
				// silence would hide a stale annotation, and overwriting would lose the work.
				ScrtArgDetector.Result r = detector.detect(t);
				if (r.isResolved() && !r.spec.toString().equals(known.get(t).toString())) {
					Msg.info(this, NAME + ": " + t + " is annotated " +
						upper(known.get(t)) + " but detection reads " + upper(r.spec) +
						"; the annotation is being used");
				}
				continue;
			}
			InlineArgSpec spec = known.get(t);
			if (spec == null) {
				Msg.info(this, NAME + ": undetermined callee " + t + " - " +
					detector.detect(t).reason + "; treated as taking no extra bytes");
			}
			else if (!spec.isEmpty()) {
				Msg.info(this, NAME + ": callee " + t + " takes " + upper(spec));
			}
			noteCallee(program, t, spec);
		}
		cachedExtras = known;
		cachedAtInstructionCount = (int) instructions;
		return known;
	}

	/**
	 * The signature written on a callee, or null if there is not a readable one.
	 *
	 * <p>A function's repeatable comment and the code unit's repeatable comment at its entry are
	 * the same storage in Ghidra -- setting either shows in both -- so there is only one slot to
	 * read, and only one to write.
	 */
	private InlineArgSpec commentSignature(Program program, Address callee) {
		return leadingSpec(program.getListing().getComment(CommentType.REPEATABLE, callee));
	}

	private static InlineArgSpec leadingSpec(String comment) {
		if (comment == null) {
			return null;
		}
		String t = comment.trim();
		int cut = t.length();
		for (int i = 0; i < t.length(); i++) {
			char ch = t.charAt(i);
			if (Character.isWhitespace(ch) || ch == '-' || ch == ':' || ch == '\u2014') {
				cut = i;
				break;
			}
		}
		return cut == 0 ? null : InlineArgSpec.parse(t.substring(0, cut));
	}

	/** The signature in the form a person writes it: W for a word, B for a byte. */
	private static String upper(InlineArgSpec spec) {
		return spec == null ? "?" : spec.toString().toUpperCase();
	}

	/**
	 * Records on the callee itself how many extra inline bytes it reads, as a repeatable comment
	 * so that it is visible at every call site. {@code extra} of -1 means the size could not be
	 * determined, which is worth saying out loud at the call sites too.
	 */
	private void noteCallee(Program program, Address callee, InlineArgSpec spec) {
		Listing listing = program.getListing();
		String existing = listing.getComment(CommentType.REPEATABLE, callee);
		boolean ours = existing != null && existing.contains(AUTO_MARKER);

		if (existing != null && !existing.isBlank() && !ours) {
			// Prose someone else wrote. Leaving it is the whole point: this analyzer gets one
			// chance to write, and anything a human touches afterwards wins.
			Msg.info(this, NAME + ": " + callee + " has a repeatable comment with no readable " +
				"signature at its start; leaving it alone. Detection reads " + upper(spec));
			return;
		}

		String wanted;
		if (spec == null) {
			wanted = "? - inline arguments undetermined; call sites assume " + inlineBytes +
				" byte(s). " + AUTO_MARKER;
		}
		else if (spec.isEmpty()) {
			// Worth stating rather than leaving blank: at a call site this is what confirms the
			// call really is just the opcode and its address.
			wanted = "NONE - no inline arguments. " + AUTO_MARKER;
		}
		else {
			wanted = upper(spec) + " - inline arguments: " + describe(spec) + ". A call occupies " +
				(1 + inlineBytes + spec.byteCount()) + " bytes. " + AUTO_MARKER;
		}

		if (!wanted.equals(existing)) {
			listing.setComment(callee, CommentType.REPEATABLE, wanted);
		}
	}

	/** Spells the signature out, since the letters alone mean little at a call site. */
	private static String describe(InlineArgSpec spec) {
		StringBuilder sb = new StringBuilder();
		for (InlineArgSpec.Kind k : spec.kinds()) {
			if (sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(k == InlineArgSpec.Kind.BYTE ? "byte"
					: k == InlineArgSpec.Kind.WORD ? "word" : "pointer");
		}
		return sb.toString();
	}

	// ---------------------------------------------------------------- returns

	private boolean markReturn(Instruction in) {
		String comment = COMMENT_PREFIX + "return";
		if (in.getFlowOverride() == FlowOverride.RETURN &&
			comment.equals(in.getComment(CommentType.EOL))) {
			return false;
		}
		in.setFlowOverride(FlowOverride.RETURN);
		in.setComment(CommentType.EOL, comment);
		return true;
	}

	// ---------------------------------------------------------------- undo

	private boolean ownsMarkup(Instruction in) {
		String c = in.getComment(CommentType.EOL);
		return c != null && c.startsWith(COMMENT_PREFIX);
	}

	/** Undoes markup applied under a previous option set. */
	private boolean removeMarkup(Program program, Instruction in, MessageLog log) {
		try {
			if (in.isFallThroughOverridden()) {
				Address from = in.getAddress().add(1);
				Address to = in.getFallThrough().subtract(1);
				if (to.compareTo(from) >= 0) {
					clearOwnedReferences(program, from, to);
					program.getListing().clearCodeUnits(from, to, false);
				}
				in.clearFallThroughOverride();
			}
			for (Reference r : in.getReferencesFrom()) {
				if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isCall()) {
					program.getReferenceManager().delete(r);
				}
			}
			in.setFlowOverride(FlowOverride.NONE);
			in.setComment(CommentType.EOL, null);
			return true;
		}
		catch (Exception e) {
			log.appendMsg(NAME,
				"Could not remove markup at " + in.getAddress() + ": " + e);
			return false;
		}
	}

	// ---------------------------------------------------------------- helpers

	/**
	 * Queues an address for disassembly when nothing meaningful is there yet. Undefined bytes are
	 * code units too, so testing merely for the presence of one would wrongly conclude the work
	 * was already done.
	 */
	private void scheduleDisassembly(Listing listing, Address a, AddressSet toDisassemble) {
		if (a != null && listing.getInstructionAt(a) == null &&
			listing.getDefinedDataAt(a) == null) {
			toDisassemble.add(a);
		}
	}

	/** @return what is wrong with the inline byte range, or null if it is usable */
	private String validate(Program program, Address start, Address end) {
		for (Address a = start; a.compareTo(end) <= 0; a = a.next()) {
			MemoryBlock block = program.getMemory().getBlock(a);
			if (block == null) {
				return "inline byte at " + a + " is not in mapped memory";
			}
			if (!block.isInitialized()) {
				return "inline byte at " + a + " is in uninitialized memory";
			}
			if (a.equals(end)) {
				break;
			}
		}
		return null;
	}

	private void clearOwnedReferences(Program program, Address start, Address end) {
		for (Address a = start; a.compareTo(end) <= 0; a = a.next()) {
			for (Reference r : program.getReferenceManager().getReferencesFrom(a)) {
				if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isData()) {
					program.getReferenceManager().delete(r);
				}
			}
			if (a.equals(end)) {
				break;
			}
		}
	}

	/**
	 * Logs every {@code LDI lo / PLO Rn / LDI hi / PHI Rn} sequence and the address it builds.
	 * This is a hint to help fill the options in — the SCRT vectors show up here — and is never
	 * acted on, because the same idiom loads ordinary pointers too.
	 */
	private void logVectorHints(Program program, TaskMonitor monitor) throws CancelledException {
		Set<String> seen = new HashSet<>();
		InstructionIterator it = program.getListing().getInstructions(true);
		Instruction[] w = new Instruction[4];
		while (it.hasNext()) {
			monitor.checkCancelled();
			System.arraycopy(w, 1, w, 0, 3);
			w[3] = it.next();
			if (w[0] == null) {
				continue;
			}
			if (!"LDI".equals(w[0].getMnemonicString()) ||
				!"PLO".equals(w[1].getMnemonicString()) ||
				!"LDI".equals(w[2].getMnemonicString()) ||
				!"PHI".equals(w[3].getMnemonicString())) {
				continue;
			}
			Register lo = w[1].getRegister(0);
			Register hi = w[3].getRegister(0);
			Scalar loVal = w[0].getScalar(0);
			Scalar hiVal = w[2].getScalar(0);
			if (lo == null || hi == null || loVal == null || hiVal == null ||
				!lo.getName().equals(hi.getName())) {
				continue;
			}
			int value = (int) ((hiVal.getUnsignedValue() << 8) | loVal.getUnsignedValue()) & 0xFFFF;
			String line = String.format("%s = %04X (loaded at %s)", lo.getName(), value,
				w[0].getAddress());
			if (seen.add(line)) {
				Msg.info(this, NAME + ": register load hint: " + line);
			}
		}
	}
}
