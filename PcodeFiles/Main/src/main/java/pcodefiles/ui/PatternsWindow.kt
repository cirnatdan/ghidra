package pcodefiles.ui

import java.awt.Dimension
import java.io.StringWriter
import javax.swing.JFrame
import javax.swing.JScrollPane
import javax.swing.JTextArea

class PatternsWindow(private val patterns: Map<String,List<String>>) : JFrame("IDAPro Patterns") {
    init {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        initTextArea(patterns)
        isVisible = true
        size = Dimension(400,600)
    }

    private fun initTextArea(patterns: Map<String, List<String>>) {
        val out = StringWriter()

        patterns.forEach { (group, p) ->
            out.write(group + System.lineSeparator())
            p.forEach {
                out.write(it + System.lineSeparator())
            }
            out.write(System.lineSeparator())
        }

        // first time loading
        val textArea = JTextArea()
        textArea.text = out.toString()
        val scrollPane = JScrollPane(textArea)
        scrollPane.name = "EDITOR_SCROLL_PANE"
        scrollPane.preferredSize = Dimension(400, 600)
        add(scrollPane)
    }
}