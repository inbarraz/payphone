// Marks the instruction at the cursor as the CDP1800 X == P inline-operand form,
// then re-disassembles it, in one keystroke.
//
// When X equals P, R(X) IS the program counter, so OUT, RET, DIS, LDXA and IRX
// swallow a byte from the instruction stream and are two bytes long instead of
// one. Nothing can infer that while disassembling, because P and X are ordinary
// data registers with no value at analysis time, so the cdp1806 module exposes a
// one-bit context field XP for saying so by hand (see REVIEW.md gaps G1 and G2).
//
// Doing it through the GUI is three steps - clear, Set Register Values..., then
// disassemble - and the dialog has to be filled in each time. This does the lot
// at the cursor, or over the selection if there is one.
//
// Known sites in the TAMAC-18 image: 0000 (DIS + 00), the 6DD5 reset block,
// 51A8 (OUT 6 + '>') and 51B1 (RET + 0x24).
//
// Everything happens in one transaction, so Undo reverts the lot. SetXPNormal is
// the inverse.
//
//@category CDP1806
//@runtime Java
//@keybinding ctrl shift X
//@menupath Tools.CDP1806.Set XP inline form
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

public class SetXPInline extends GhidraScript {

    @Override
    public void run() throws Exception {
        ProgramContext ctx = currentProgram.getProgramContext();
        Register xp = ctx.getRegister("XP");
        if (xp == null) {
            popup("This program's language has no XP context register.\n\n"
                + "It needs the cdp1806 module from this repository, at a build that\n"
                + "defines contextreg / XP. Rebuild and reinstall the extension, then\n"
                + "re-open the program so the new language is picked up.");
            return;
        }

        // Work over the selection if there is one, otherwise the cursor address.
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

        // Order matters. The context value is read when the instruction is
        // created, so an existing code unit has to go first; setting the value
        // under a live instruction changes nothing you can see.
        clearListing(start, end);
        ctx.setValue(xp, start, end, BigInteger.ONE);
        disassemble(start);

        println("XP = 1 (inline form) over " + start + ".." + end
                + "; re-disassembled from " + start + ".");
    }
}
