import QtQuick

Item {
    // This source is stable across analyzer revisions. H4 now discovers the
    // network-to-execution chain that the old sink-local classifier missed.
    property string payload: xhr.responseText
    Component.onCompleted: Quickshell.execDetached(payload)
}
