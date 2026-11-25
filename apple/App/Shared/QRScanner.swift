#if os(iOS)
import AVFoundation
import SwiftUI
import UIKit

/// Scans the profile QR code on the downloads page. Scanning runs on the
/// device; nothing is looked up on the network.
struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var problem: String?
    let found: (String) -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if let problem {
                    VStack(spacing: 16) {
                        Text(problem)
                            .foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) {
                                UIApplication.shared.open(url)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding()
                } else {
                    QRScanner(found: found, failed: { problem = $0 })
                        .ignoresSafeArea()
                    Text("Point the camera at a Porta profile QR code.")
                        .font(.callout)
                        .foregroundStyle(.white)
                        .padding(10)
                        .background(.black.opacity(0.6), in: Capsule())
                        .frame(maxHeight: .infinity, alignment: .bottom)
                        .padding(.bottom, 40)
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .tint(.white)
                }
            }
        }
    }
}

/// The camera preview that reports the first QR code it reads.
struct QRScanner: UIViewControllerRepresentable {
    let found: (String) -> Void
    let failed: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.found = found
        controller.failed = failed
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var found: ((String) -> Void)?
        var failed: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var preview: AVCaptureVideoPreviewLayer?
        private var reported = false

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized:
                configure()
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { granted in
                    DispatchQueue.main.async {
                        granted ? self.configure() : self.deny()
                    }
                }
            default:
                deny()
            }
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.bounds
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            let session = session
            DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
        }

        private func deny() {
            failed?(String(localized: "Camera access is needed to scan a QR code. Allow it in Settings, or enter the details manually."))
        }

        private func configure() {
            guard let camera = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: camera),
                  session.canAddInput(input)
            else {
                failed?(String(localized: "The camera is unavailable. Try again or enter the details manually."))
                return
            }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else {
                failed?(String(localized: "The camera is unavailable. Try again or enter the details manually."))
                return
            }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
            self.preview = preview
            let session = session
            DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !reported,
                  let code = metadataObjects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first
            else { return }
            reported = true
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            found?(code)
        }
    }
}
#endif
