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

        clearListing(start, end);
        ctx.setValue(xp, start, end, BigInteger.ZERO);
        disassemble(start);

        println("XP = 0 (normal form) over " + start + ".." + end
                + "; re-disassembled from " + start + ".");
    }
}
