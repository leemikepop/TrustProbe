package io.github.leemikepop.trustprobe

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.leemikepop.trustprobe.ui.ControllerGateway
import io.github.leemikepop.trustprobe.ui.PackageManagerCatalog
import io.github.leemikepop.trustprobe.ui.RoomHistory
import io.github.leemikepop.trustprobe.ui.ServiceTunnelLauncher
import io.github.leemikepop.trustprobe.ui.TrustProbeRoot
import io.github.leemikepop.trustprobe.ui.TrustProbeTheme
import io.github.leemikepop.trustprobe.ui.TrustProbeViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val app = application as TrustProbeApp
        val factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T = TrustProbeViewModel(
                catalog = PackageManagerCatalog(app),
                session = ControllerGateway(app.sessionController),
                history = RoomHistory(app.sessionDao, app.sessionStore),
                tunnel = ServiceTunnelLauncher(app),
                selfPackage = packageName,
                savedState = extras.createSavedStateHandle(),
            ) as T
        }
        setContent {
            TrustProbeTheme {
                TrustProbeRoot(viewModel<TrustProbeViewModel>(factory = factory))
            }
        }
    }
}
