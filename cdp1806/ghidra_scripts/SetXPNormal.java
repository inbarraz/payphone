// The inverse of SetXPInline: clears the XP context field at the cursor so the
// instruction goes back to its normal one-byte form, then re-disassembles.
//
// Useful when a site turns out not to use the X == P idiom after all, or to back
// out an experiment without walking the undo stack.
//
// Deliberately standalone rather than extending SetXPInline: Ghidra compiles
// each script on its own, and inheritance between two of them is not worth the
// risk of one failing to build for the sake of thirty shared lines.
//
//@category CDP1806
//@runtime Java
//@keybinding ctrl shift Z
//@menupath Tools.CDP1806.Set XP normal form
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

public class SetXPNormal extends GhidraScript {

    @Override
    public void run() throws Exception {
        ProgramContext ctx = currentProgram.getProgramContext();
        Register xp = ctx.getRegister("XP");
        if (xp == null) {
            popup("This program's language has no XP context register.\n\n"
                + "It needs the cdp1806 module from this repository, at a build that\n"
                + "defines contextreg / XP.");
            return;
        }

        Address start, end;
        AddressSetView sel = currentSelection;
        // A selection is almost always a mistake here. XP must hold at the
        // *instruction*, and DIS/RET reload X from their operand, so a SEX
        // earlier in a block does not put the block in the inline form - see
        // the 2419 counter-example in README.md. Refuse a range unless the
        // caller insists.
        if (sel != null && !sel.isEmpty() && !sel.getMinAddress().equals(sel.getMaxAddress())) {
            if (!askYesNo("Set XP over a whole range?",
                    "The selection spans " + sel.getMinAddress() + ".." + sel.getMaxAddress()
                  + ".\n\nXP must hold at each instruction, and DIS/RET reload X from their\n"
                  + "operand - so a SEX earlier in a block does NOT make the block inline.\n"
                  + "Blanket-setting a range silently turns one-byte OUT/RET/DIS into two\n"
                  + "and shifts everything after them.\n\n"
                  + "Only the 6DD5 reset block is known to be range-safe.\n\nProceed anyway?")) {
                println("Cancelled; nothing changed.");
                return;
            }
        }

        if (sel != null && !sel.isEmpty()) {
            start = sel.getMinAddress();
            end = sel.getMaxAddress();
        } else if (currentAddress != null) {
            start = currentAddress;
            end = currentAddress;
        } else {
            popup("Put the cursor on an instruction first.");
            return;
        }

        // Clear one byte PAST the end as well. At a single address,
        // clearListing(start,start) removes only the code unit holding the
        // opcode; if the operand byte is already its own instruction - which is
        // exactly the 51B2 DEC R4 case this exists to fix - it survives, the new
        // two-byte instruction overlaps it, and disassembly is rejected.
        Address clearEnd = end;
        try {
            clearEnd = end.add(1);
        } catch (Exception e) {
            // end of address space; clearing just `end` is the best we can do
        }
        clearListing(start, clearEnd);
        ctx.setValue(xp, start, end, BigInteger.ZERO);

        // disassemble() returns false when it could not lay an instruction
        // down. Reporting success regardless is how a silent failure looks.
        if (!disassemble(start)) {
            popup("Set XP at " + start + ", but disassembly FAILED there.\n\n"
                + "Usually a neighbouring instruction still overlaps. Clear a few\n"
                + "bytes by hand and disassemble again.");
            println("XP set over " + start + ".." + end + " but disassemble(" + start
                    + ") returned false.");
            return;
        }

        println("XP = 0 (normal form) over " + start + ".." + end
                + "; re-disassembled from " + start + ".");
    }
}
