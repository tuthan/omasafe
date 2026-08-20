import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "io.github.tuthan.omasafe"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null

  function open() {
    panel.open()
  }

  function close() {
    panel.close()
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    contentWidth: fittedContentWidth(Style.space(360))
    contentHeight: fittedContentHeight(content.implicitHeight)

    Column {
      id: content
      width: panel.contentWidth - panel.padding * 2
      spacing: Style.space(10)

      Text {
        text: "OMASAFE"
        color: bar ? bar.foreground : Color.foreground
        font.family: bar ? bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.title
        font.bold: true
      }

      Text {
        width: parent.width
        wrapMode: Text.WordWrap
        text: root.hostWidget && root.hostWidget.alertCount > 0
          ? root.hostWidget.alertCount + " item(s) need review"
          : "No new actionable changes detected."
        color: bar ? bar.foreground : Color.foreground
        font.family: bar ? bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.body
      }

      Text {
        width: parent.width
        wrapMode: Text.WordWrap
        text: "OmaSafe reports changes and coverage limits. It does not declare plugins safe."
        color: Util.alpha(bar ? bar.foreground : Color.foreground, 0.64)
        font.family: bar ? bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.caption
      }

      Button {
        text: "Run scan"
        onClicked: if (root.hostWidget) root.hostWidget.runScan()
      }
    }
  }
}
