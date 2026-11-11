import AppIntents
import Foundation

// 系统动作只调用既有IPC，不实现或修改转发逻辑。
@available(iOS 16.0, *)
private enum HotspotActionClient {
    struct ActionError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func request(_ command: String) throws -> [AnyHashable: Any] {
        var error: NSError?
        guard let response = IHRequest(["command": command], &error) else {
            throw ActionError(message: error?.localizedDescription ?? "热点服务拒绝请求。")
        }
        guard (response["ok"] as? NSNumber)?.boolValue == true else {
            throw ActionError(message: response["error"] as? String ?? "热点服务拒绝请求。")
        }
        return response
    }

    static func execute(_ command: String) async throws -> Bool {
        // 使用串行独立队列完成阻塞IPC，避免阻塞系统界面；toggle只解析一次目标。
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let before = try request("status")
                    guard (before["enabled"] as? NSNumber)?.boolValue == true else {
                        throw ActionError(message: "请先在 iOSHotspot 中启用服务。")
                    }
                    let current = (before["hotspotOn"] as? NSNumber)?.boolValue ?? false
                    let desired = command == "toggle" ? !current : command == "start"
                    if desired != current { _ = try request(desired ? "start" : "stop") }
                    let deadline = Date().addingTimeInterval(5)
                    while true {
                        let state = try request("status")
                        if (state["hotspotOn"] as? NSNumber)?.boolValue == desired {
                            continuation.resume(returning: desired)
                            return
                        }
                        guard Date() < deadline else {
                            throw ActionError(message: "系统尚未确认热点状态，请打开应用查看。")
                        }
                        Thread.sleep(forTimeInterval: 0.2)
                    }
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
    private static let queue = DispatchQueue(label: "com.newbie.ioshotspot.intents")
}

@available(iOS 16.0, *)
struct StartHotspotIntent: AppIntent {
    static var title: LocalizedStringResource = "开启热点"
    static var description = IntentDescription("使用 iOSHotspot 已选择的来源开启系统个人热点。")
    static var openAppWhenRun = false
    func perform() async throws -> some IntentResult & ProvidesDialog {
        _ = try await HotspotActionClient.execute("start")
        return .result(dialog: "热点已开启。")
    }
}

@available(iOS 16.0, *)
struct StopHotspotIntent: AppIntent {
    static var title: LocalizedStringResource = "关闭热点"
    static var description = IntentDescription("关闭 iOSHotspot 管理的系统个人热点。")
    static var openAppWhenRun = false
    func perform() async throws -> some IntentResult & ProvidesDialog {
        _ = try await HotspotActionClient.execute("stop")
        return .result(dialog: "热点已关闭。")
    }
}

@available(iOS 16.0, *)
struct ToggleHotspotIntent: AppIntent {
    static var title: LocalizedStringResource = "切换热点"
    static var description = IntentDescription("读取真实状态后开启或关闭热点。")
    static var openAppWhenRun = false
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let on = try await HotspotActionClient.execute("toggle")
        return .result(dialog: on ? "热点已开启。" : "热点已关闭。")
    }
}

@available(iOS 16.0, *)
struct HotspotAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: StartHotspotIntent(), phrases: ["使用\(.applicationName)开启热点"], shortTitle: "开启热点", systemImageName: "personalhotspot")
        AppShortcut(intent: StopHotspotIntent(), phrases: ["使用\(.applicationName)关闭热点"], shortTitle: "关闭热点", systemImageName: "stop.circle")
        AppShortcut(intent: ToggleHotspotIntent(), phrases: ["使用\(.applicationName)切换热点"], shortTitle: "切换热点", systemImageName: "switch.2")
    }
}
