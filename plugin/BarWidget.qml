import QtQuick
import qs.Commons
import qs.Ui
import Quickshell.Io

BarWidget {
  id: root
  moduleName: "io.github.tuthan.omasafe"

  property int alertCount: 0
  property int outstandingCount: 0
  property int newCount: 0
  property var alerts: []
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
      root.outstandingCount = result.outstanding || root.alertCount
      root.newCount = result.new || 0
      root.alerts = result.alerts || []
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
      if (exitCode !== 0 && exitCode !== 3) root.scanState = "unavailable"
    }
  }

  Timer {
    interval: 300000
    running: true
    repeat: true
    onTriggered: root.runScan()
  }

  Component.onCompleted: root.runScan()

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
    text: root.scanState === "unavailable" || root.scanState === "unknown"
      ? "?" : (root.outstandingCount > 0 ? "!" : "✓")
    slotSize: Style.bar.statusSlot
    tooltipText: root.outstandingCount > 0
      ? "OmaSafe: " + root.outstandingCount + " item(s) need review"
      : "OmaSafe: " + root.scanState
    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.runScan()
      else if (mouseButton === Qt.MiddleButton && panelLoader.item) panelLoader.item.open()
    }
  }
}
