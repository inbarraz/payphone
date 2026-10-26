package cdp1806;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The inline-argument signature of a CDP1806 subroutine.
 *
 * <p>A {@code SCAL} instruction leaves R(N) pointing at the bytes immediately following the
 * four-byte instruction. A subroutine may consume some of those bytes as arguments -- with
 * {@code LDA R3} for a byte, or {@code RLXA Rn} while X == 3 for a 16-bit word -- before
 * {@code SRET R3} returns to whatever R3 then points at. The number and width of those
 * consumed bytes is a property of the callee, and is what this class records.
 */
public class InlineArgSpec {

	public enum Kind {
		BYTE(1, "b"),
		WORD(2, "w"),
		POINTER(2, "p");

		public final int size;
		public final String code;

		Kind(int size, String code) {
			this.size = size;
			this.code = code;
		}

		static Kind fromCode(String s) {
			for (Kind k : values()) {
				if (k.code.equalsIgnoreCase(s)) {
					return k;
				}
			}
			return null;
		}
	}

	public static final InlineArgSpec NONE = new InlineArgSpec(Collections.emptyList());

	private final List<Kind> kinds;

	public InlineArgSpec(List<Kind> kinds) {
		this.kinds = Collections.unmodifiableList(new ArrayList<>(kinds));
	}

	public List<Kind> kinds() {
		return kinds;
	}

	public boolean isEmpty() {
		return kinds.isEmpty();
	}

	/** Total number of inline bytes this subroutine consumes. */
	public int byteCount() {
		int n = 0;
		for (Kind k : kinds) {
			n += k.size;
		}
		return n;
	}

	/** Renders as the override-file argspec, e.g. {@code "p,b"} or {@code "none"}. */
	@Override
	public String toString() {
		if (kinds.isEmpty()) {
			return "none";
		}
		StringBuilder sb = new StringBuilder();
		for (Kind k : kinds) {
			if (sb.length() > 0) {
				sb.append(',');
			}
			sb.append(k.code);
		}
		return sb.toString();
	}

	/**
	 * Parses an argspec such as {@code "p,b"}, {@code "w"} or {@code "none"}. Empty fields are
	 * rejected rather than quietly dropped, so a stray comma is reported as a bad line instead
	 * of silently changing the signature.
	 *
	 * @return the parsed spec, or null if the text is not a valid argspec
	 */
	public static InlineArgSpec parse(String text) {
		String t = text.trim();
		if (t.isEmpty()) {
			return null;
		}
		if (t.equalsIgnoreCase("none")) {
			return NONE;
		}
		List<Kind> kinds = new ArrayList<>();
		for (String part : t.split(",", -1)) {
			Kind k = Kind.fromCode(part.trim());
			if (k == null) {
				return null;
			}
			kinds.add(k);
		}
		return new InlineArgSpec(kinds);
	}
}
