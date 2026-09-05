package dev.porta.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraInfoUnavailableException
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.lifecycle.Lifecycle
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class QrScannerActivity : ComponentActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var message: TextView
    private lateinit var retry: Button
    private val executor = Executors.newSingleThreadExecutor()
    private val decoder = QrFrameDecoder()
    private val paused = AtomicBoolean(false)
    private var cameraProvider: ProcessCameraProvider? = null
    private var camera: Camera? = null
    private var analysis: ImageAnalysis? = null
    private var preview: Preview? = null
    private var cameraStarting = false
    private var cameraGeneration = 0
    private var lastFrameAt = 0L
    private var showingError = false

    private val cameraPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            showingError = false
            paused.set(false)
            retry.visibility = View.GONE
            message.setText(R.string.qr_scanning)
            startCamera()
        } else {
            showError(R.string.qr_camera_permission_denied)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = Color.rgb(8, 17, 31)
        window.navigationBarColor = Color.rgb(8, 17, 31)
        setResult(RESULT_CANCELED)
        setContentView(buildContent())
        if (savedInstanceState == null && !hasCameraPermission()) {
            cameraPermission.launch(Manifest.permission.CAMERA)
        } else if (!hasCameraPermission()) {
            showError(R.string.qr_camera_permission_denied)
        }
    }

    override fun onResume() {
        super.onResume()
        if (hasCameraPermission() && !showingError) startCamera()
    }

    override fun onStop() {
        releaseCamera()
        super.onStop()
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    private fun buildContent(): View {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(8, 17, 31))
            addView(TextView(this@QrScannerActivity).apply {
                setText(R.string.scan_qr_code)
                textSize = 23f
                setTextColor(Color.rgb(242, 247, 252))
                setTypeface(typeface, Typeface.BOLD)
                setPadding(0, 0, 0, dp(8))
                ViewCompat.setAccessibilityHeading(this, true)
            })
            addView(TextView(this@QrScannerActivity).apply {
                setText(R.string.qr_scan_help)
                textSize = 14f
                setTextColor(Color.rgb(148, 163, 184))
                setPadding(0, 0, 0, dp(12))
            })
            previewView = PreviewView(this@QrScannerActivity).apply {
                implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                scaleType = PreviewView.ScaleType.FIT_CENTER
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            addView(previewView, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
            message = TextView(this@QrScannerActivity).apply {
                setText(R.string.qr_scanning)
                textSize = 14f
                gravity = Gravity.CENTER
                setTextColor(Color.rgb(242, 247, 252))
                setPadding(0, dp(12), 0, dp(8))
                accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
            }
            addView(message)
            retry = Button(this@QrScannerActivity).apply {
                setText(R.string.qr_retry)
                isAllCaps = false
                minHeight = dp(48)
                visibility = View.GONE
                setOnClickListener {
                    showingError = false
                    paused.set(false)
                    visibility = View.GONE
                    message.setText(R.string.qr_scanning)
                    if (hasCameraPermission()) startCamera()
                    else cameraPermission.launch(Manifest.permission.CAMERA)
                }
            }
            addView(retry, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(LinearLayout(this@QrScannerActivity).apply {
                gravity = Gravity.CENTER
                addView(Button(this@QrScannerActivity).apply {
                    setText(R.string.enter_manually)
                    isAllCaps = false
                    minHeight = dp(48)
                    setOnClickListener {
                        setResult(RESULT_ENTER_MANUALLY)
                        finish()
                    }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(Button(this@QrScannerActivity).apply {
                    setText(R.string.cancel)
                    isAllCaps = false
                    minHeight = dp(48)
                    setOnClickListener { finish() }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            })
        }
        page.setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT >= 30) {
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                page.setPadding(dp(20) + safe.left, dp(16) + safe.top, dp(20) + safe.right, dp(12) + safe.bottom)
            } else {
                page.setPadding(
                    dp(20) + insets.systemWindowInsetLeft, dp(16) + insets.systemWindowInsetTop,
                    dp(20) + insets.systemWindowInsetRight, dp(12) + insets.systemWindowInsetBottom,
                )
            }
            insets
        }
        page.requestApplyInsets()
        return page
    }

    private fun hasCameraPermission(): Boolean =
        checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    private fun startCamera() {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
            isFinishing || cameraStarting || analysis != null || showingError
        ) return
        cameraStarting = true
        val generation = ++cameraGeneration
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            if (generation != cameraGeneration || isFinishing || isDestroyed) return@addListener
            cameraStarting = false
            try {
                val provider = future.get()
                cameraProvider = provider
                val selector = when {
                    provider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) -> CameraSelector.DEFAULT_BACK_CAMERA
                    provider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) -> CameraSelector.DEFAULT_FRONT_CAMERA
                    else -> {
                        showError(R.string.qr_camera_unavailable)
                        return@addListener
                    }
                }
                val rotation = previewView.display?.rotation ?: android.view.Surface.ROTATION_0
                val cameraPreview = Preview.Builder().setTargetRotation(rotation).build()
                val cameraAnalysis = ImageAnalysis.Builder()
                    .setTargetRotation(rotation)
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                    .setResolutionSelector(
                        ResolutionSelector.Builder().setResolutionStrategy(
                            ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER),
                        ).build(),
                    )
                    .build()
                preview = cameraPreview
                analysis = cameraAnalysis
                cameraPreview.setSurfaceProvider(previewView.surfaceProvider)
                cameraAnalysis.setAnalyzer(executor) { image -> analyze(image, generation) }
                camera = provider.bindToLifecycle(this, selector, cameraPreview, cameraAnalysis)
                camera?.cameraInfo?.cameraState?.observe(this) { state ->
                    if (state.error != null && generation == cameraGeneration) cameraFailed()
                }
            } catch (_: ExecutionException) {
                cameraFailed()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                cameraFailed()
            } catch (_: CameraInfoUnavailableException) {
                cameraFailed()
            } catch (_: SecurityException) {
                cameraFailed()
            } catch (_: IllegalArgumentException) {
                cameraFailed()
            } catch (_: IllegalStateException) {
                cameraFailed()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun analyze(image: ImageProxy, generation: Int) {
        try {
            val now = SystemClock.elapsedRealtime()
            if (paused.get() || now - lastFrameAt < 250) return
            lastFrameAt = now
            val plane = image.planes.firstOrNull() ?: return
            val crop = image.cropRect
            val frame = QrLuminanceFrame.fromPlane(
                plane.buffer, image.width, image.height, plane.rowStride, plane.pixelStride,
                crop.left, crop.top, crop.width(), crop.height(), image.imageInfo.rotationDegrees,
            ) ?: return
            val payload = decoder.decode(frame) ?: return
            val valid = ProfileQr.parse(payload) != null
            if (!paused.compareAndSet(false, true)) return
            runOnUiThread {
                if (generation != cameraGeneration || isFinishing || isDestroyed) {
                    if (!showingError) paused.set(false)
                    return@runOnUiThread
                }
                if (valid) {
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_PAYLOAD, payload))
                    finish()
                } else {
                    showError(R.string.qr_invalid_profile)
                }
            }
        } finally {
            image.close()
        }
    }

    private fun showError(resource: Int) {
        showingError = true
        paused.set(true)
        message.setText(resource)
        retry.visibility = View.VISIBLE
    }

    private fun cameraFailed() {
        releaseCamera()
        showError(R.string.qr_camera_unavailable)
    }

    private fun releaseCamera() {
        cameraGeneration++
        cameraStarting = false
        camera?.cameraInfo?.cameraState?.removeObservers(this)
        camera = null
        analysis?.let {
            it.clearAnalyzer()
            cameraProvider?.unbind(it)
        }
        preview?.let { cameraProvider?.unbind(it) }
        analysis = null
        preview = null
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        internal const val EXTRA_PAYLOAD = "dev.porta.android.profile_qr"
        internal const val RESULT_ENTER_MANUALLY = RESULT_FIRST_USER
    }
}
