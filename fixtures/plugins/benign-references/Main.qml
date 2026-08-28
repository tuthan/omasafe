import QtQuick

Item {
    // R-2 negatives: none of these may produce a finding or a
    // sink-reference-rejected limitation.

    // Icon names are not path-shaped.
    property string iconName: "media-playback-start"

    // Format strings are not load references, even when path-shaped;
    // they sit outside every verified sink position.
    readonly property string labelPattern: "%1/%2.json"

    Text {
        text: labelPattern.arg(1).arg(2)
    }

    // URLs in comments are invisible to detection.
    // spec: https://example.test/plugin-spec

    // A non-sink unresolvable path-shaped string stays inventory context.
    property string styleHint: "themes/legacy/panel.conf"

    // A sink-position reference that resolves in the tree forms an edge
    // and discloses nothing.
    Loader { source: "./Widget.qml" }
}
