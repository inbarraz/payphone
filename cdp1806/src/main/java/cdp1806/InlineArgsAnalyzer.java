package cdp1806;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import generic.jar.ResourceFile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Marks up CDP1806 {@code SCAL} calls that carry their arguments inline, in the caller, directly
 * after the four-byte call instruction.
 *
 * <p>For each such call the analyzer corrects the instruction's fall-through so the argument
 * bytes stop being disassembled as code, lays them down as typed data, and -- where a 16-bit
 * argument resolves to a real address -- adds a reference so the pointed-at data picks up an
 * xref.
 *
 * <p>Signatures come from {@link InlineArgDetector}, which reads them out of the callee itself.
 * Anything it cannot work out with confidence can be stated in an override file; see
 * {@code data/inline_args.txt}.
 */
public class InlineArgsAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "CDP1806 inline call arguments";
	private static final String DESCRIPTION =
		"Finds SCAL calls whose arguments are stored inline after the call instruction, " +
			"corrects the fall-through so those bytes are not disassembled as code, types " +
			"them, and creates references for pointer arguments.";

	private static final String OPTION_OVERRIDE_FILE = "Override file";
	private static final String OPTION_OVERRIDE_FILE_DESC =
		"Optional path to an additional inline-argument override file. Entries here take " +
			"precedence over both auto-detection and the module's own data/inline_args.txt. " +
			"A relative path is resolved against Ghidra's working directory, so prefer an " +
			"absolute one.";

	private static final String OPTION_REFERENCES = "Create pointer references";
	private static final String OPTION_REFERENCES_DESC =
		"Create a reference from a 16-bit inline argument to the address it holds. A 'w' " +
			"argument does so only when that address is in initialized memory; a 'p' argument " +
			"does so for any mapped address, including uninitialized RAM.";

	private static final String MODULE_OVERRIDE_FILE = "inline_args.txt";
	private static final String PROCESSOR = "cdp1806";

	/**
	 * Marks an end-of-line comment as this analyzer's own. Markup is only ever rewritten or
	 * removed where this marker is present, so hand-made annotations are left alone.
	 */
	private static final String COMMENT_PREFIX = "inline args: ";

	private String overrideFilePath = "";
	private boolean createReferences = true;

	public InlineArgsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Needs SCAL instructions and their call references to exist first.
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PROCESSOR.equalsIgnoreCase(program.getLanguage().getProcessor().toString());
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_OVERRIDE_FILE, OptionType.STRING_TYPE, "", null,
			OPTION_OVERRIDE_FILE_DESC);
		options.registerOption(OPTION_REFERENCES, true, null, OPTION_REFERENCES_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		overrideFilePath = options.getString(OPTION_OVERRIDE_FILE, "");
		createReferences = options.getBoolean(OPTION_REFERENCES, true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Call sites are revisited across passes rather than only when newly added: a callee's
		// signature often only becomes knowable after its own body has been disassembled, which
		// can happen long after the call site itself.
		List<Instruction> callSites = findCallSites(program, monitor, log);
		if (callSites.isEmpty()) {
			return false;
		}

		Overrides overrides = loadOverrides(program, log);
		Map<Address, InlineArgDetector.CalleeInfo> signatures =
			resolveSignatures(program, callSites, overrides, monitor);

		int changed = 0;
		AddressSet toDisassemble = new AddressSet();
		Set<Address> sitePinsUsed = new HashSet<>();

		for (Instruction in : callSites) {
			monitor.checkCancelled();
			// A signature pinned to this call site wins over the callee's own: a variadic
			// callee reads a different number of bytes depending on how it was called.
			InlineArgSpec spec = overrides.bySite.get(in.getAddress());
			if (spec != null) {
				sitePinsUsed.add(in.getAddress());
			}
			else {
				Address target = callTarget(in);
				InlineArgDetector.CalleeInfo info = target == null ? null : signatures.get(target);
				spec = info == null ? null : info.spec;
			}
			if (spec == null) {
				// Nothing known. Markup from an earlier run is left in place rather than
				// removed, because a signature that has merely become unknowable -- a body that
				// is not disassembled yet, say -- is not evidence the markup was wrong.
				continue;
			}
			Change c = reconcileSite(program, in, spec, toDisassemble, log);
			if (c != Change.NONE) {
				changed++;
				Msg.info(this, NAME + ": " + in.getAddress() +
					(c == Change.REMOVED ? " markup removed" : " -> " + spec));
			}
		}

		if (!toDisassemble.isEmpty()) {
			DisassembleCommand cmd = new DisassembleCommand(toDisassemble, null, true);
			cmd.applyTo(program, monitor);
		}

		reportUnusedSitePins(overrides, sitePinsUsed);
		reportUnresolved(program, callSites, signatures, overrides, monitor);
		reportSummary(callSites, signatures, changed);
		return changed > 0;
	}

	/** What reconciling one call site did. */
	private enum Change {
		NONE, APPLIED, REMOVED
	}

	private List<Instruction> findCallSites(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		List<Instruction> result = new ArrayList<>();
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			if (!"SCAL".equals(in.getMnemonicString())) {
				continue;
			}
			// Only SCAL R3 is understood. SCAL R4 points R4 at the arguments instead, so a
			// signature derived from R3 movement would not describe it.
			if (!InlineArgDetector.isR3Call(in)) {
				Msg.info(this, NAME + ": skipped " + in.getAddress() + " - " + in +
					" passes arguments through a register other than R3");
				continue;
			}
			result.add(in);
		}
		return result;
	}

	private static Address callTarget(Instruction in) {
		return InlineArgDetector.callTarget(in);
	}

	/**
	 * Works out a signature for every call target, repeating until nothing new is learned. The
	 * repetition matters because a subroutine that itself makes an inline-argument call can only
	 * be understood once that inner call's signature is known.
	 */
	private Map<Address, InlineArgDetector.CalleeInfo> resolveSignatures(Program program,
			List<Instruction> callSites, Overrides overrides, TaskMonitor monitor)
			throws CancelledException {

		Set<Address> targets = new HashSet<>();
		for (Instruction in : callSites) {
			Address t = callTarget(in);
			if (t != null) {
				targets.add(t);
			}
		}

		Map<Address, InlineArgDetector.CalleeInfo> known = new HashMap<>();
		// A stated signature says nothing about the X the callee leaves behind, so a caller
		// stepping over such a call has to treat X as unknown from there on.
		for (Map.Entry<Address, InlineArgSpec> e : overrides.byCallee.entrySet()) {
			known.put(e.getKey(), new InlineArgDetector.CalleeInfo(e.getValue(),
				InlineArgDetector.X_UNKNOWN));
		}
		InlineArgDetector detector =
			new InlineArgDetector(program, known::get, overrides.bySite::get);

		boolean progress = true;
		while (progress) {
			monitor.checkCancelled();
			progress = false;
			for (Address t : targets) {
				if (known.containsKey(t)) {
					continue;
				}
				InlineArgDetector.Result r = detector.detectWithReason(t);
				if (r.isResolved()) {
					known.put(t, new InlineArgDetector.CalleeInfo(r.spec, r.exitX));
					progress = true;
				}
			}
		}
		return known;
	}

	// ---------------------------------------------------------------- markup

	/**
	 * Brings one call site's markup into line with {@code spec}, adding, rewriting or removing
	 * it as needed. Only markup this analyzer owns -- identified by the comment marker -- is
	 * ever rewritten or removed.
	 *
	 * @return what, if anything, changed
	 */
	private Change reconcileSite(Program program, Instruction in, InlineArgSpec spec,
			AddressSet toDisassemble, MessageLog log) {

		Listing listing = program.getListing();
		Address argStart = in.getMaxAddress().next();
		if (argStart == null) {
			return Change.NONE;
		}

		boolean owned = ownsMarkup(in);
		int oldBytes = owned && in.isFallThroughOverridden() ? distance(argStart,
			in.getFallThrough()) : 0;

		if (spec.isEmpty()) {
			return owned ? removeMarkup(program, in, argStart, oldBytes, toDisassemble, log)
					: Change.NONE;
		}

		int newBytes = spec.byteCount();
		Address resume;
		Address argEnd;
		try {
			argEnd = argStart.add(newBytes - 1);
			resume = argStart.add(newBytes);
		}
		catch (RuntimeException e) {
			Msg.info(this, NAME + ": " + in.getAddress() +
				" - arguments would run past the end of memory; skipped");
			return Change.NONE;
		}

		// Everything is validated before anything is written. The clear has to come before the
		// data is laid down, and an analyzer cannot roll back the enclosing transaction, so a
		// failure half way would leave the listing worse than it found it.
		String problem = validate(program, argStart, argEnd);
		if (problem != null) {
			Msg.info(this, NAME + ": " + in.getAddress() + " - " + problem + "; skipped");
			return Change.NONE;
		}

		if (owned && in.isFallThroughOverridden() && resume.equals(in.getFallThrough()) &&
			layoutMatches(listing, argStart, spec) && referencesMatch(program, argStart, spec)) {
			return Change.NONE; // already exactly right
		}

		try {
			// Clear the whole of both the old and the new extent: a signature that got shorter
			// would otherwise leave its former trailing argument behind as orphaned data.
			Address clearEnd = argStart.add(Math.max(oldBytes, newBytes) - 1);
			if (!program.getMemory().contains(clearEnd)) {
				clearEnd = argEnd;
			}
			clearOwnedReferences(program, argStart, clearEnd);
			listing.clearCodeUnits(argStart, clearEnd, false);

			Address at = argStart;
			List<String> described = new ArrayList<>();
			for (InlineArgSpec.Kind kind : spec.kinds()) {
				described.add(layDown(program, at, kind));
				at = at.add(kind.size);
			}

			in.setFallThrough(resume);
			in.setComment(CommentType.EOL, COMMENT_PREFIX + String.join(", ", described));

			scheduleDisassembly(listing, resume, toDisassemble);
			return Change.APPLIED;
		}
		catch (Exception e) {
			log.appendMsg(NAME,
				"Could not mark up inline arguments at " + in.getAddress() + ": " + e);
			return Change.NONE;
		}
	}

	/** Undoes markup this analyzer previously applied, for a callee now known to take none. */
	private Change removeMarkup(Program program, Instruction in, Address argStart, int oldBytes,
			AddressSet toDisassemble, MessageLog log) {
		if (oldBytes <= 0 && !in.isFallThroughOverridden()) {
			if (ownsMarkup(in)) {
				in.setComment(CommentType.EOL, null);
				return Change.APPLIED;
			}
			return Change.NONE;
		}
		try {
			Address end = argStart.add(Math.max(oldBytes, 1) - 1);
			clearOwnedReferences(program, argStart, end);
			program.getListing().clearCodeUnits(argStart, end, false);
			in.clearFallThroughOverride();
			in.setComment(CommentType.EOL, null);
			scheduleDisassembly(program.getListing(), argStart, toDisassemble);
			return Change.REMOVED;
		}
		catch (Exception e) {
			log.appendMsg(NAME,
				"Could not remove inline-argument markup at " + in.getAddress() + ": " + e);
			return Change.NONE;
		}
	}

	private boolean ownsMarkup(Instruction in) {
		String c = in.getComment(CommentType.EOL);
		return c != null && c.startsWith(COMMENT_PREFIX);
	}

	private static int distance(Address from, Address to) {
		if (to == null || !to.getAddressSpace().equals(from.getAddressSpace())) {
			return 0;
		}
		long d = to.getOffset() - from.getOffset();
		return d > 0 && d < 64 ? (int) d : 0;
	}

	/** @return a description of what is wrong with the argument range, or null if it is usable */
	private String validate(Program program, Address start, Address end) {
		for (Address a = start; a.compareTo(end) <= 0; a = a.next()) {
			MemoryBlock block = program.getMemory().getBlock(a);
			if (block == null) {
				return "argument byte at " + a + " is not in mapped memory";
			}
			if (!block.isInitialized()) {
				return "argument byte at " + a + " is in uninitialized memory";
			}
			if (a.equals(end)) {
				break;
			}
		}
		return null;
	}

	private boolean layoutMatches(Listing listing, Address argStart, InlineArgSpec spec) {
		Address at = argStart;
		for (InlineArgSpec.Kind kind : spec.kinds()) {
			Data d = listing.getDefinedDataAt(at);
			if (d == null || d.getLength() != kind.size) {
				return false;
			}
			at = at.add(kind.size);
		}
		return true;
	}

	/** True when the references at the argument bytes are already what the options call for. */
	private boolean referencesMatch(Program program, Address argStart, InlineArgSpec spec) {
		Address at = argStart;
		for (InlineArgSpec.Kind kind : spec.kinds()) {
			boolean wanted = createReferences && wantsReference(program, at, kind);
			boolean present = false;
			for (Reference r : program.getReferenceManager().getReferencesFrom(at)) {
				if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isData()) {
					present = true;
				}
			}
			if (wanted != present) {
				return false;
			}
			at = at.add(kind.size);
		}
		return true;
	}

	/**
	 * Whether this argument should carry a reference. This is where {@code w} and {@code p}
	 * differ: a plain word only points at something if that something is really there, while a
	 * pointer is taken at its word for any mapped address, which is what makes RAM targets
	 * referenceable.
	 */
	private boolean wantsReference(Program program, Address at, InlineArgSpec.Kind kind) {
		if (kind == InlineArgSpec.Kind.BYTE) {
			return false;
		}
		Address target = targetOf(program, at);
		if (target == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(target);
		if (block == null) {
			return false;
		}
		return kind == InlineArgSpec.Kind.POINTER || block.isInitialized();
	}

	private Address targetOf(Program program, Address at) {
		Integer value = readWord(program, at);
		if (value == null) {
			return null;
		}
		try {
			return program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(value & 0xFFFF);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	/** Lays one argument down as data and returns a short description of it. */
	private String layDown(Program program, Address at, InlineArgSpec.Kind kind) throws Exception {
		Listing listing = program.getListing();
		if (kind == InlineArgSpec.Kind.BYTE) {
			listing.createData(at, (DataType) ByteDataType.dataType);
			return String.format("%02X", program.getMemory().getByte(at) & 0xFF);
		}

		listing.createData(at, (DataType) WordDataType.dataType);
		Integer value = readWord(program, at);
		if (value == null) {
			return "??";
		}
		if (createReferences && wantsReference(program, at, kind)) {
			program.getReferenceManager()
					.addMemoryReference(at, targetOf(program, at), RefType.DATA,
						SourceType.ANALYSIS, 0);
			return String.format("%04X ->", value & 0xFFFF);
		}
		return String.format("%04X", value & 0xFFFF);
	}

	/** Removes only the references this analyzer would have created. */
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
	 * Queues the resume address for disassembly when nothing meaningful is there. Undefined
	 * bytes are code units too, so an "is there a code unit" test would wrongly conclude the
	 * work was already done.
	 */
	private void scheduleDisassembly(Listing listing, Address resume, AddressSet toDisassemble) {
		if (listing.getInstructionAt(resume) == null &&
			listing.getDefinedDataAt(resume) == null) {
			toDisassemble.add(resume);
		}
	}

	/** Reads a big-endian 16-bit value, independent of any memory endianness setting. */
	private static Integer readWord(Program program, Address at) {
		try {
			int hi = program.getMemory().getByte(at) & 0xFF;
			int lo = program.getMemory().getByte(at.add(1)) & 0xFF;
			return (hi << 8) | lo;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	// ---------------------------------------------------------------- reporting

	private void reportUnusedSitePins(Overrides overrides, Set<Address> used) {
		for (Address a : overrides.bySite.keySet()) {
			if (!used.contains(a)) {
				Msg.info(this, NAME + ": override for call site " + a +
					" matches no SCAL R3 instruction");
			}
		}
	}

	/**
	 * Logs each call target we could not pin down, with the reason, so it is clear what needs an
	 * override and why. Informational only.
	 */
	private void reportUnresolved(Program program, List<Instruction> callSites,
			Map<Address, InlineArgDetector.CalleeInfo> signatures, Overrides overrides,
			TaskMonitor monitor) throws CancelledException {

		Set<Address> unresolved = new TreeSet<>();
		for (Instruction in : callSites) {
			monitor.checkCancelled();
			if (overrides.bySite.containsKey(in.getAddress())) {
				continue;
			}
			Address target = callTarget(in);
			if (target == null) {
				Msg.info(this, NAME + ": skipped " + in.getAddress() +
					" - cannot determine the call target");
			}
			else if (!signatures.containsKey(target)) {
				unresolved.add(target);
			}
		}
		if (unresolved.isEmpty()) {
			return;
		}
		InlineArgDetector detector =
			new InlineArgDetector(program, signatures::get, overrides.bySite::get);
		for (Address t : unresolved) {
			monitor.checkCancelled();
			Msg.info(this, NAME + ": undetermined " + t + " - " +
				detector.detectWithReason(t).reason);
		}
	}

	private void reportSummary(List<Instruction> callSites,
			Map<Address, InlineArgDetector.CalleeInfo> signatures, int changed) {
		Set<Address> allTargets = new HashSet<>();
		for (Instruction in : callSites) {
			Address t = callTarget(in);
			if (t != null) {
				allTargets.add(t);
			}
		}
		int resolved = 0;
		for (Address t : allTargets) {
			if (signatures.containsKey(t)) {
				resolved++;
			}
		}
		// Informational, so it goes to the log rather than the MessageLog: anything in the
		// MessageLog makes Ghidra raise a "warnings/errors during analysis" dialog.
		Msg.info(this, NAME + ": changed " + changed + " call site(s); " + resolved + " of " +
			allTargets.size() + " call targets resolved across " + callSites.size() +
			" call site(s).");
	}

	// ---------------------------------------------------------------- overrides

	/** Signatures stated in the override files: by callee, and pinned to individual call sites. */
	private static class Overrides {
		final Map<Address, InlineArgSpec> byCallee = new LinkedHashMap<>();
		final Map<Address, InlineArgSpec> bySite = new LinkedHashMap<>();
	}

	private Overrides loadOverrides(Program program, MessageLog log) {
		Overrides result = new Overrides();

		ResourceFile moduleFile = null;
		try {
			moduleFile = Application.getModuleDataFile(PROCESSOR, MODULE_OVERRIDE_FILE);
		}
		catch (IOException e) {
			// The module's own override file is optional; absence is not an error.
		}
		if (moduleFile != null) {
			try (Reader r = new InputStreamReader(moduleFile.getInputStream())) {
				readOverrides(program, r, moduleFile.getName(), result, log);
			}
			catch (IOException e) {
				// Present but unreadable is a real problem, unlike simply absent.
				log.appendMsg(NAME, "Could not read bundled overrides " + moduleFile.getName() +
					": " + e.getMessage());
			}
		}

		if (overrideFilePath != null && !overrideFilePath.isBlank()) {
			File f = new File(overrideFilePath.trim());
			if (!f.isAbsolute()) {
				Msg.info(this, NAME + ": override file path is relative; resolved to " +
					f.getAbsolutePath());
			}
			if (!f.isFile()) {
				log.appendMsg(NAME, "Override file not found: " + f.getAbsolutePath());
			}
			else {
				try (Reader r = new FileReader(f)) {
					readOverrides(program, r, f.getPath(), result, log);
				}
				catch (IOException e) {
					log.appendMsg(NAME, "Could not read " + f + ": " + e.getMessage());
				}
			}
		}
		return result;
	}

	/**
	 * Reads lines of the form {@code <callee-address> <argspec>}, where argspec is a
	 * comma-separated list of b (byte), w (word) and p (pointer), or "none". Blank lines and
	 * anything after a '#' are ignored. An address written as {@code @addr} pins the signature
	 * to that one call site instead of to a callee.
	 *
	 * <p>A line {@code program <text>} gates everything after it on the program's name
	 * containing that text, so firmware-specific entries do not escape onto another image that
	 * merely happens to share the processor. {@code program *} opens it up again.
	 *
	 * <p>Later entries win, so a file named in the analyzer option overrides the module's own.
	 */
	private void readOverrides(Program program, Reader reader, String sourceName,
			Overrides into, MessageLog log) throws IOException {

		BufferedReader br = new BufferedReader(reader);
		String line;
		int lineNo = 0;
		boolean applies = true;
		while ((line = br.readLine()) != null) {
			lineNo++;
			int hash = line.indexOf('#');
			if (hash >= 0) {
				line = line.substring(0, hash);
			}
			line = line.trim();
			if (line.isEmpty()) {
				continue;
			}
			String[] parts = line.split("\\s+", 2);
			if (parts.length != 2) {
				log.appendMsg(NAME,
					sourceName + ":" + lineNo + ": expected '<address> <argspec>'");
				continue;
			}
			if ("program".equalsIgnoreCase(parts[0])) {
				String want = parts[1].trim();
				applies = "*".equals(want) ||
					program.getName().toLowerCase().contains(want.toLowerCase());
				continue;
			}
			if (!applies) {
				continue;
			}
			InlineArgSpec spec = InlineArgSpec.parse(parts[1]);
			if (spec == null) {
				log.appendMsg(NAME,
					sourceName + ":" + lineNo + ": bad argspec '" + parts[1].trim() + "'");
				continue;
			}
			boolean perSite = parts[0].startsWith("@");
			Address addr = parseAddress(program, perSite ? parts[0].substring(1) : parts[0]);
			if (addr == null) {
				log.appendMsg(NAME,
					sourceName + ":" + lineNo + ": bad address '" + parts[0] + "'");
				continue;
			}
			(perSite ? into.bySite : into.byCallee).put(addr, spec);
		}
	}

	private static Address parseAddress(Program program, String text) {
		String hex = text.toLowerCase().startsWith("0x") ? text.substring(2) : text;
		try {
			return program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(Long.parseLong(hex, 16));
		}
		catch (RuntimeException e) {
			// NumberFormatException for a non-number, AddressOutOfBoundsException for one
			// outside this 16-bit space. Either way it is one bad line, not a failed pass.
			return null;
		}
	}
}
