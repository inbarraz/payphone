// Removes references attached to the REGISTER operand of CDP1806 SCAL instructions.
//
// SCAL carries its link register as operand 0 and its call target as operand 1.
// The SLEIGH semantics assign inst_next to the link register, so Ghidra's constant
// propagation decides that register holds a code address and attaches spurious DATA
// references to operand 0. The listing then reads
//     SCAL R3=>LAB_4546,FUN_6fff
// instead of
//     SCAL R3,FUN_6fff
//
// This script deletes only operand-0 references on SCAL. The call target reference
// on operand 1 is left alone. Run it again after any re-analysis that recreates them.
// Everything happens in one transaction, so Undo reverts the lot.
//
//@category CDP1806
//@author
//@runtime Java
//@menupath Tools.CDP1806.Remove SCAL Register References
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class RemoveScalRegisterRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        ReferenceManager rm = currentProgram.getReferenceManager();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int seen = 0, withRefs = 0, removed = 0;
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction in = it.next();
            if (!"SCAL".equals(in.getMnemonicString())) {
                continue;
            }
            seen++;
            Reference[] refs = in.getOperandReferences(0);
            if (refs.length == 0) {
                continue;
            }
            withRefs++;
            StringBuilder sb = new StringBuilder();
            for (Reference r : refs) {
                sb.append(' ').append(r.getToAddress()).append('(').append(r.getReferenceType())
                  .append(')');
                rm.delete(r);
                removed++;
            }
            println(in.getAddress() + " removed:" + sb);
        }
        println("----");
        println("SCAL instructions examined : " + seen);
        println("had operand-0 references   : " + withRefs);
        println("references removed         : " + removed);
    }
}
