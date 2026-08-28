import QtQuick

// R-1 indicator scope: H0 probe C 2026-08-27 — remote directory imports are
// scanner-intercepted on the pinned runtime (the URL normalizes onto a
// relative filesystem path and is dropped), so these spellings record the
// indicator, never the High remote-component-load rule. Both the
// `as`-qualified and bare forms, with and without a qmldir, are covered.
import "https://plugins.example/remote/qml" as Remote
import "https://plugins.example/bare"

// Local relative directory imports are ordinary QML and must stay silent;
// ./widgets carries a qmldir.
import "./widgets" as Widgets

Item {
    Loader {
        source: "./widgets/Widget.qml"
    }
}
