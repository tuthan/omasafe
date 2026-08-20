import QtQuick
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "io.github.tuthan.omasafe"

  property int alertCount: 0
  property string scanState: "unknown"
  property string limitation: ""

  visible: !vertical
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function applyScan(output) {
    try {
      var report = JSON.parse(output)
      var result = report.result || {}
      root.alertCount = (result.alerts || []).length
      root.scanState = result.quiet === true ? "quiet" : "attention"
      root.limitation = ""
    } catch (error) {
      root.scanState = "unavailable"
      root.limitation = "CLI report unavailable"
    }
  }

  function runScan() {
    if (!scanProcess.running) scanProcess.running = true
  }

  Process {
    id: scanProcess
    command: ["omasafe-cli", "scan", "--format", "json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyScan(text())
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) root.scanState = "unavailable"
    }
  }

  Timer {
    interval: 300000
    running: true
    repeat: true
    onTriggered: root.runScan()
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      item.hostWidget = root
      item.anchorItem = button
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.alertCount > 0 ? "!" : "✓"
    slotSize: Style.bar.statusSlot
    tooltipText: root.alertCount > 0
      ? "OmaSafe: " + root.alertCount + " item(s) need review"
      : "OmaSafe: " + root.scanState
    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.runScan()
      else if (mouseButton === Qt.MiddleButton && panelLoader.item) panelLoader.item.open()
    }
  }
}
