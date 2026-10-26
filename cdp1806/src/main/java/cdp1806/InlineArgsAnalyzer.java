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

import generic.jar.ResourceFile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
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
			"precedence over both auto-detection and the module's own data/inline_args.txt.";

	private static final String OPTION_REFERENCES = "Create pointer references";
	private static final String OPTION_REFERENCES_DESC =
		"Create a reference from a 16-bit inline argument to the address it holds, when that " +
			"address is inside the program's memory.";

	private static final String MODULE_OVERRIDE_FILE = "inline_args.txt";

	/** Signatures stated in the override files: by callee, and pinned to individual call sites. */
	private static class Overrides {
		final Map<Address, InlineArgSpec> byCallee = new LinkedHashMap<>();
		final Map<Address, InlineArgSpec> bySite = new LinkedHashMap<>();
	}
	private static final String PROCESSOR = "cdp1806";

	private String overrideFilePath = "";
	private boolean createReferences = true;

	public InlineArgsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Needs SCAL instructions and their call references to exist first.
		setPriority(ghidra.app.services.AnalysisPriority.CODE_ANALYSIS.after());
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
		List<Instruction> callSites = findScalInstructions(program, monitor);
		if (callSites.isEmpty()) {
			return false;
		}

		Overrides overrides = loadOverrides(program, log);
		Map<Address, InlineArgSpec> signatures = resolveSignatures(program, callSites, overrides,
			monitor);

		int marked = 0;
		AddressSet toDisassemble = new AddressSet();
		for (Instruction in : callSites) {
			monitor.checkCancelled();
			// A signature pinned to this call site wins over the callee's own: a variadic
			// callee reads a different number of bytes depending on how it was called.
			InlineArgSpec spec = overrides.bySite.get(in.getAddress());
			if (spec == null) {
				Address target = callTarget(in);
				spec = target == null ? null : signatures.get(target);
			}
			if (spec == null || spec.isEmpty()) {
				continue;
			}
			if (applyMarkup(program, in, spec, toDisassemble, log)) {
				marked++;
				Msg.info(this, NAME + ": " + in.getAddress() + " -> " + spec);
			}
		}

		if (!toDisassemble.isEmpty()) {
			DisassembleCommand cmd = new DisassembleCommand(toDisassemble, null, true);
			cmd.applyTo(program, monitor);
		}

		reportUnresolved(program, callSites, signatures, overrides, monitor);

		// Informational, so it goes to the log rather than the MessageLog: anything in the
		// MessageLog makes Ghidra raise a "warnings/errors during analysis" dialog.
		int resolvedTargets = 0;
		Set<Address> allTargets = new HashSet<>();
		for (Instruction in : callSites) {
			Address t = callTarget(in);
			if (t != null) {
				allTargets.add(t);
			}
		}
		for (Address t : allTargets) {
			if (signatures.containsKey(t)) {
				resolvedTargets++;
			}
		}
		Msg.info(this, NAME + ": marked up " + marked + " new call site(s); " +
			resolvedTargets + " of " + allTargets.size() + " call targets resolved across " +
			callSites.size() + " call site(s).");
		return marked > 0;
	}

	private List<Instruction> findScalInstructions(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<Instruction> result = new ArrayList<>();
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			if ("SCAL".equals(in.getMnemonicString())) {
				result.add(in);
			}
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
	private Map<Address, InlineArgSpec> resolveSignatures(Program program,
			List<Instruction> callSites, Overrides overrides, TaskMonitor monitor)
			throws CancelledException {

		Set<Address> targets = new HashSet<>();
		for (Instruction in : callSites) {
			Address t = callTarget(in);
			if (t != null) {
				targets.add(t);
			}
		}

		Map<Address, InlineArgSpec> known = new HashMap<>(overrides.byCallee);
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
				InlineArgSpec spec = detector.detect(t);
				if (spec != null) {
					known.put(t, spec);
					progress = true;
				}
			}
		}
		return known;
	}

	/**
	 * Logs each call target we could not pin down, with the reason, so it is clear what needs an
	 * override and why. Informational only.
	 */
	private void reportUnresolved(Program program, List<Instruction> callSites,
			Map<Address, InlineArgSpec> signatures, Overrides overrides, TaskMonitor monitor)
			throws CancelledException {

		Set<Address> unresolved = new java.util.TreeSet<>();
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

	/**
	 * @return true if anything was changed at this call site
	 */
	private boolean applyMarkup(Program program, Instruction in, InlineArgSpec spec,
			AddressSet toDisassemble, MessageLog log) {

		Listing listing = program.getListing();
		Address argStart = in.getMaxAddress().next();
		if (argStart == null) {
			return false;
		}
		int total = spec.byteCount();
		Address argEnd = argStart.add(total - 1);
		Address resume = argStart.add(total);
		if (!program.getMemory().contains(argEnd)) {
			return false;
		}

		boolean alreadyCorrect =
			in.isFallThroughOverridden() && resume.equals(in.getFallThrough());
		if (alreadyCorrect && listing.getDataAt(argStart) != null &&
			listing.getDataAt(argStart).isDefined()) {
			return false; // nothing left to do; keeps repeat passes quiet
		}

		try {
			listing.clearCodeUnits(argStart, argEnd, false);

			Address at = argStart;
			List<String> described = new ArrayList<>();
			for (InlineArgSpec.Kind kind : spec.kinds()) {
				described.add(describeAndType(program, at, kind));
				at = at.add(kind.size);
			}

			in.setFallThrough(resume);
			in.setComment(CommentType.EOL, "inline args: " + String.join(", ", described));

			if (listing.getCodeUnitAt(resume) == null) {
				toDisassemble.add(resume);
			}
			return true;
		}
		catch (Exception e) {
			log.appendMsg(NAME,
				"Could not mark up inline arguments at " + in.getAddress() + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Lays down one argument as data and returns a short human-readable description of it.
	 */
	private String describeAndType(Program program, Address at, InlineArgSpec.Kind kind)
			throws Exception {

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
		Address target =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(value & 0xFFFF);
		boolean pointerish =
			kind == InlineArgSpec.Kind.POINTER || program.getMemory().contains(target);
		if (createReferences && pointerish && program.getMemory().contains(target)) {
			program.getReferenceManager()
					.addMemoryReference(at, target, RefType.DATA, SourceType.ANALYSIS, 0);
			return String.format("%04X ->", value & 0xFFFF);
		}
		return String.format("%04X", value & 0xFFFF);
	}

	/** Reads a big-endian 16-bit value, independent of any memory endianness setting. */
	private static Integer readWord(Program program, Address at) {
		try {
			int hi = program.getMemory().getByte(at) & 0xFF;
			int lo = program.getMemory().getByte(at.add(1)) & 0xFF;
			return (hi << 8) | lo;
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	// ---------------------------------------------------------------- overrides

	private Overrides loadOverrides(Program program, MessageLog log) {
		Overrides result = new Overrides();
		try {
			ResourceFile moduleFile =
				Application.getModuleDataFile(PROCESSOR, MODULE_OVERRIDE_FILE);
			try (Reader r = new InputStreamReader(moduleFile.getInputStream())) {
				readOverrides(program, r, moduleFile.getName(), result, log);
			}
		}
		catch (IOException e) {
			// The module's own override file is optional; absence is not an error.
		}

		if (overrideFilePath != null && !overrideFilePath.isBlank()) {
			File f = new File(overrideFilePath.trim());
			if (!f.isFile()) {
				log.appendMsg(NAME, "Override file not found: " + f);
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
	 * to that one call site instead of to a callee. Later entries win, so a file named in the
	 * analyzer option overrides the module's own.
	 */
	private void readOverrides(Program program, Reader reader, String sourceName,
			Overrides into, MessageLog log) throws IOException {

		BufferedReader br = new BufferedReader(reader);
		String line;
		int lineNo = 0;
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
			InlineArgSpec spec = InlineArgSpec.parse(parts[1]);
			if (spec == null) {
				log.appendMsg(NAME,
					sourceName + ":" + lineNo + ": bad argspec '" + parts[1].trim() + "'");
				continue;
			}
			// A leading '@' pins the signature to one call site rather than to a callee.
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
		catch (NumberFormatException | NullPointerException e) {
			return null;
		}
	}
}
