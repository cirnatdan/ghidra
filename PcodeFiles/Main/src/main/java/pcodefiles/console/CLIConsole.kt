package pcodefiles.console

import ghidra.app.services.ConsoleService
import java.io.PrintWriter
import java.lang.Exception

class CLIConsole : ConsoleService {
    override fun addMessage(originator: String, message: String) {
//        println("[$originator] $message!!")
    }

    override fun addErrorMessage(originator: String, message: String) {
        //println("[$originator!!] $message!!")
    }

    override fun addException(originator: String, exc: Exception) {
//        println("[$originator!!] $exc!!")
//        exc?.printStackTrace()
    }

    override fun clearMessages() {
        TODO("Not yet implemented")
    }

    override fun print(msg: String) {
        println(msg)
    }

    override fun println(msg: String) {
        println(msg)
    }

    override fun printError(errmsg: String) {
        println(errmsg)
    }

    override fun printlnError(errmsg: String) {
        println(errmsg)
    }

    override fun getStdOut(): PrintWriter {
        return PrintWriter(System.out)
    }

    override fun getStdErr(): PrintWriter {
        return PrintWriter(System.err)
    }

    override fun getTextLength(): Int {
        TODO("Not yet implemented")
    }

    override fun getText(offset: Int, length: Int): String {
        TODO("Not yet implemented")
    }
}