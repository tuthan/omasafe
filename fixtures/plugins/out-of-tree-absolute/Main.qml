import QtQuick

Item {
    // R-1: an absolute path loads content from outside the reviewed tree.
    // Unreviewed out-of-tree load that bypasses commit-bound review —
    // not a sandbox escape; there is no runtime sandbox.
    Loader { source: "/tmp/staged.qml" }
}
