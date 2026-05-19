// InfraRed ESF Helper — macOS EndpointSecurity Framework 이벤트 수집기
// Entitlement 필요: com.apple.developer.endpoint-security.client
// 빌드: swiftc -o esf_helper main.swift -framework EndpointSecurity
// 실행: sudo ./esf_helper --json
//
// 출력: 각 이벤트를 한 줄 JSON으로 stdout에 출력
// 형식: {"event_type":"EXEC","pid":1234,"ppid":1,"uid":0,"gid":0,
//        "process_path":"/bin/sh","timestamp":"2026-01-01T00:00:00Z",
//        "is_signed":true,"target_path":""}

import Foundation
import EndpointSecurity

// MARK: - JSON 출력 유틸
func jsonLine(_ dict: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: dict),
          let str = String(data: data, encoding: .utf8) else { return }
    print(str)
    fflush(stdout)
}

func isoNow() -> String {
    let fmt = ISO8601DateFormatter()
    fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fmt.string(from: Date())
}

// MARK: - 코드서명 확인
func isSignedBinary(at path: String) -> Bool {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    proc.arguments = ["-v", path]
    proc.standardOutput = Pipe()
    proc.standardError = Pipe()
    try? proc.run()
    proc.waitUntilExit()
    return proc.terminationStatus == 0
}

// MARK: - ESF 구독
var client: OpaquePointer?

let result = es_new_client(&client) { _, message in
    let eventType: String
    var pid: Int32 = 0
    var ppid: Int32 = 0
    var uid: UInt32 = 0
    var gid: UInt32 = 0
    var processPath = ""
    var targetPath = ""
    var isSigned = true

    let proc = message.pointee.process.pointee
    pid = proc.audit_token.__data.4  // audit_token PID 추출 (simplified)
    ppid = proc.ppid
    uid = proc.audit_token.__data.1
    gid = proc.audit_token.__data.2

    if let pathPtr = proc.executable.pointee.path.data {
        processPath = String(cString: pathPtr)
    }

    switch message.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        eventType = "EXEC"
        isSigned = isSignedBinary(at: processPath)

    case ES_EVENT_TYPE_NOTIFY_FORK:
        eventType = "FORK"

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        eventType = "EXIT"

    case ES_EVENT_TYPE_NOTIFY_CREATE:
        eventType = "CREATE"
        let createEvent = message.pointee.event.create
        if case .existing_file = createEvent.destination {} else {
            // new file — path 추출 시도
            targetPath = processPath  // simplified
        }

    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        eventType = "UNLINK"
        if let tp = message.pointee.event.unlink.target.pointee.path.data {
            targetPath = String(cString: tp)
        }

    case ES_EVENT_TYPE_NOTIFY_OPEN:
        eventType = "OPEN"

    case ES_EVENT_TYPE_NOTIFY_WRITE:
        eventType = "WRITE"

    case ES_EVENT_TYPE_NOTIFY_RENAME:
        eventType = "RENAME"

    case ES_EVENT_TYPE_NOTIFY_MOUNT:
        eventType = "MOUNT"

    case ES_EVENT_TYPE_AUTH_EXEC:
        eventType = "AUTH_EXEC"
        isSigned = isSignedBinary(at: processPath)
        // 거부하지 않고 AUTH_ALLOW로 통과시킴 (모니터링 전용)
        es_respond_auth_result(client!, message, ES_AUTH_RESULT_ALLOW, false)

    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
        eventType = "SIGNAL"

    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
        eventType = "KEXTLOAD"
        if let bundleIDPtr = message.pointee.event.kextload.identifier.data {
            targetPath = String(cString: bundleIDPtr)  // kext_identifier로 활용
        }

    default:
        return
    }

    var dict: [String: Any] = [
        "event_type": eventType,
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "gid": gid,
        "process_path": processPath,
        "timestamp": isoNow(),
        "is_signed": isSigned,
        "target_path": targetPath,
    ]

    jsonLine(dict)
}

guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
    fputs("ESF 클라이언트 생성 실패: \(result.rawValue) — Entitlement 확인 필요\n", stderr)
    exit(1)
}

// 구독할 이벤트 타입 목록
let events: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_UNLINK,
    ES_EVENT_TYPE_NOTIFY_OPEN,
    ES_EVENT_TYPE_NOTIFY_WRITE,
    ES_EVENT_TYPE_NOTIFY_RENAME,
    ES_EVENT_TYPE_NOTIFY_MOUNT,
    ES_EVENT_TYPE_AUTH_EXEC,
    ES_EVENT_TYPE_NOTIFY_SIGNAL,
    ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
]

let subResult = es_subscribe(client!, events, UInt32(events.count))
guard subResult == ES_RETURN_SUCCESS else {
    fputs("ESF 구독 실패: \(subResult.rawValue)\n", stderr)
    exit(1)
}

fputs("ESF 구독 시작 — \(events.count)개 이벤트 타입\n", stderr)

// 메인 런루프 (Ctrl+C로 종료)
signal(SIGINT) { _ in
    es_delete_client(client!)
    exit(0)
}

RunLoop.main.run()
