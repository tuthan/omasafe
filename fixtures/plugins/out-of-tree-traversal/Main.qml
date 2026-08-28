import QtQuick

Item {
    // R-1: a traversal reference escapes the plugin tree and loads content
    // (for instance a sibling plugin's file) that was never part of the
    // reviewed commit.
    Loader { source: "../outside/W.qml" }
}
