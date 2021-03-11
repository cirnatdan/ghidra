package pcodefiles.analysis

import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

/**
 * Helper class for use in python scripts
 */
class UtilsHelper : FlatProgramAPI, Utils {

    constructor(currentProgram: Program, monitor: TaskMonitor) : super(currentProgram, monitor)
}