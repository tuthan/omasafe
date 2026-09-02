import QtQuick

Item {
    // Deliberately exceeds the 16-level expression bound. The result must
    // stay visible as partial coverage rather than being reported clean.
    property string deeplyComposed: "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x"
}
