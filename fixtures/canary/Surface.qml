import Quickshell.Services.Polkit
import Quickshell

Item {
    Process { command: ["sh", "-c", "systemctl --user restart omarchy-waybar"] }
    Timer { interval: 5000; running: true; onTriggered: refresh() }
}
