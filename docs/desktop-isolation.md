# Desktop Isolation — Headful GUI in Psroot

Psroot can run **headful GUI applications** (like Google Chrome) fully sandboxed
inside a container where:

1. The browser binary is **staged INTO the container rootfs** (hardlinked from host)
2. **AppContainer** prevents access to ANY host file, registry key, or named object
3. An **isolated Desktop** makes the GUI invisible and prevents cross-window interaction

The browser runs at `{rootfs}\Chrome\chrome.exe` — it is NOT the host Chrome.
It cannot escape the container.

## How It Works

### Staging (Binary Isolation)

Chrome's 500+ files are **hardlinked** from the host install into the container's
rootfs. This uses zero extra disk space (hardlinks share the same on-disk data)
but gives the container its own path:

```
Host:       C:\Program Files\Google\Chrome\Application\chrome.exe  (original)
Container:  C:\...\rootfs\Chrome\chrome.exe                        (hardlink)
```

The AppContainer SID is granted read+execute (RX) ACL on the rootfs. The process
CANNOT access any path outside the rootfs.

### Desktop (GUI Isolation)

Windows supports multiple Desktop objects within a single Window Station
(`WinSta0`). Every process belongs to exactly one desktop. Processes on
different desktops:

- **Cannot see** each other's windows
- **Cannot send messages** to each other's windows  
- **Cannot enumerate** windows on other desktops
- **Cannot inject input** into other desktops

```
┌─────────────────────────────────────────────────────────┐
│  Window Station: WinSta0 (your login session)           │
│                                                         │
│  ┌───────────────────┐  ┌───────────────────────────┐  │
│  │ Default           │  │ Psroot-chrome-demo        │  │
│  │ (you see this)    │  │ (invisible to you)        │  │
│  │                   │  │                           │  │
│  │ Explorer, VS Code │  │ Chrome runs headful here  │  │
│  │ your apps         │  │ GPU-accelerated           │  │
│  └───────────────────┘  └───────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Key Properties

| Property | Value |
|----------|-------|
| Rendering | Full GPU / DWM (not headless, not software-only) |
| Visibility | Invisible to user |
| Input isolation | No cross-desktop message passing |
| Admin required | No |
| Hypervisor | Not needed |
| OS support | Windows 10+ |

## Important: The Browser Runs INSIDE the Container

The Chrome binary is **not** executed from `C:\Program Files\...`. It is:

1. **Probed** on the host (found at `C:\Program Files\Google\Chrome\Application\`)
2. **Staged** into the container rootfs via hardlinks (539+ files, zero extra disk)
3. **Accessible** only via `{rootfs}\Chrome\chrome.exe`
4. **ACL-protected** — only the container's AppContainer SID has access

```
┌─────────────────────────────────────────────────────────────┐
│ Container Rootfs                                             │
│                                                             │
│  Chrome\                    ← Hardlinked from host install  │
│    chrome.exe                                               │
│    chrome_elf.dll                                            │
│    resources.pak                                             │
│    ...539 files                                             │
│  Users\ContainerUser\                                        │
│    ChromeData\             ← Profile (writable)             │
│  Temp\                     ← Temp dir (writable)            │
│                                                             │
│  AppContainer SID: S-1-15-2-xxxxx has RX on Chrome\         │
│  AppContainer SID: S-1-15-2-xxxxx has F on Users\ & Temp\   │
└─────────────────────────────────────────────────────────────┘

Host files: INACCESSIBLE (no ACL grant → access denied)
```

**Zero extra disk space**: hardlinks point to the same on-disk blocks as the
host's Chrome install. When the container is destroyed, only the hardlinks are
removed — the host Chrome is untouched.

## Usage

### Full Sandbox (Recommended) — Staged + AppContainer + Desktop

```rust
use psroot_container::sandbox::spawn_gui_plan;
use psroot_types::config::{ContainerConfig, NetworkAccess};

// 1. Resolve Chrome from host
let resolver = psroot_shell_resolver::Resolver::new(catalog_root);
let plan = resolver.resolve(
    &ShellRequest { name: "chrome".into(), ..Default::default() },
    &ResolveContext { rootfs: &rootfs, network: NetworkAccess::Full, .. },
)?;

// 2. Spawn inside container with GUI isolation
let config = ContainerConfig {
    rootfs_path: rootfs.to_string(),
    network: NetworkAccess::Full,
    ..Default::default()
};

// Chrome is:
//   - STAGED into rootfs (hardlinked, 539 files)
//   - Running in AppContainer (cannot access host files)
//   - On an isolated desktop (windows invisible)
let (sid, exit_code) = spawn_gui_plan(&plan, &config)?;
```

### Quick Demo — Desktop Isolation Only (Lighter, Less Secure)

```rust
use psroot_desktop::{DesktopConfig, IsolatedDesktop};

let config = DesktopConfig {
    appcontainer_sid: None,
    name: Some("my-browser".to_string()),
};
let desktop = IsolatedDesktop::create(&config)?;
let proc = desktop.spawn_process(
    r#""C:\...\rootfs\Chrome\chrome.exe" --no-first-run https://example.com"#,
    None, false, 0, None,
)?;
proc.wait();
```

## Google Chrome Example

The container crate ships with a full sandboxed example:

```powershell
# Run Chrome sandboxed (staged into rootfs + isolated desktop)
cargo run --example chrome-sandboxed -p psroot-container -- --timeout 10

# With custom URL
cargo run --example chrome-sandboxed -p psroot-container -- --url https://github.com --timeout 30
```

**Output:**
```
╔══════════════════════════════════════════════════════════════╗
║  psroot: Sandboxed Chrome (AppContainer + Desktop)          ║
╠══════════════════════════════════════════════════════════════╣
║  Chrome is STAGED INTO the container rootfs (not host path) ║
║  AppContainer: cannot access host files/registry            ║
║  Desktop:      windows invisible to user                    ║
╠══════════════════════════════════════════════════════════════╣
║  URL:     https://example.com                               ║
║  Timeout: 10 seconds                                        ║
╚══════════════════════════════════════════════════════════════╝

[1/6] Host Chrome found: C:\Program Files\Google\Chrome\Application
[2/6] Container rootfs: C:\Users\...\Temp\psroot-containers\chrome-sandbox-17312
[3/6] Staging Chrome into container (hardlink tree)...
       Staged to: ...\rootfs\Chrome\chrome.exe
       Files staged: 539 (hardlinked, zero extra disk space)
[4/6] Creating isolated desktop...
       Desktop: WinSta0\Psroot-chrome-sandbox-17312
[5/6] Launching sandboxed Chrome...
       Binary: ...\rootfs\Chrome\chrome.exe (INSIDE container rootfs)
       NOT host path, NOT C:\Program Files\...
       PID: 33248

  ┌─────────────────────────────────────────────────────┐
  │ Chrome is now running INSIDE the psroot container:   │
  │                                                      │
  │   Binary:    {rootfs}\Chrome\chrome.exe              │
  │   Profile:   {rootfs}\Users\ContainerUser\ChromeData │
  │   Temp:      {rootfs}\Temp                           │
  │                                                      │
  │   ✗ Cannot access C:\Users\*                         │
  │   ✗ Cannot access host registry                      │
  │   ✗ Cannot see your windows                          │
  │   ✓ Has network (for loading pages)                  │
  │   ✓ GPU rendering active (DWM)                       │
  └─────────────────────────────────────────────────────┘

[6/6] Waiting 10 seconds then terminating...
       Chrome terminated after 10 seconds.

Cleaning up rootfs...
✓ Container destroyed. Chrome ran sandboxed with zero host access.
```

## Verifying Chrome Is Actually Running Headful

While the example is running, you can confirm Chrome is truly headful (not
headless) by checking its process tree:

```powershell
# See Chrome's multi-process architecture (GPU process = headful proof)
Get-Process chrome | Format-Table Id, ProcessName, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet64/1MB,1)}} -AutoSize
```

A headful Chrome spawns ~15-25 processes including:
- Browser process (main)
- GPU process (proof of real rendering)
- Renderer processes (one per tab)
- Network service
- Audio service

A headless Chrome spawns fewer processes and has **no GPU process**.

## Use Cases

| Use Case | How |
|----------|-----|
| Browser automation without `--headless` | Desktop isolation keeps it invisible |
| Screenshot/PDF generation with full rendering | GPU process = accurate rendering |
| Untrusted web content isolation | AppContainer + Desktop = double barrier |
| CI/CD browser tests on Windows | No display needed, Chrome runs headful |
| Puppeteer/Playwright without headless mode | Set `DISPLAY` equivalent via lpDesktop |

## Combining with Puppeteer/Playwright

Since Chrome runs headful inside the container, you can use Puppeteer's
`connect()` via `--remote-debugging-port`. The port is accessible from
the host because AppContainer allows outbound loopback (with exemption):

```rust
// Chrome inside container, listening on debug port
let plan = /* resolve chrome */;
plan.args.push("--remote-debugging-port=9222".into());
let (sid, exit_code) = spawn_gui_plan(&plan, &config)?;
```

```javascript
// From host Node.js — connect to sandboxed Chrome
const browser = await puppeteer.connect({
    browserWSEndpoint: 'ws://127.0.0.1:9222/...'
});
// Full headful rendering — screenshots are pixel-perfect
// Chrome cannot access your filesystem but CAN load web pages
```

## Generic App Staging (`psroot gui`)

The `psroot gui` command can run **any** Windows app in an isolated container
without needing a catalog file. It automatically detects the app root, hardlinks
the entire directory tree, and launches on an isolated desktop.

### Usage

```bash
# Run any installed app
psroot gui "C:\Program Files\SomeApp\app.exe"

# With arguments
psroot gui "C:\Program Files\Google\Chrome\Application\chrome.exe" -- --no-first-run https://example.com

# With timeout (terminate after N seconds, 0 = wait forever)
psroot gui "C:\path\to\app.exe" --timeout 30

# Disable network access
psroot gui "C:\path\to\app.exe" --no-network

# Override app root (for non-standard layouts)
psroot gui "C:\path\to\bin\app.exe" --app-root "C:\path\to"

# Exclude patterns from staging
psroot gui "C:\path\to\app.exe" --exclude "*.log" --exclude "**/cache/**"

# Stage additional host directories
psroot gui "C:\path\to\app.exe" --extra-dir "C:\shared\plugins:Plugins"
```

### How It Works

1. **Detect app root** — Heuristic: if exe is in `bin/`, `app/`, or `cli/` subfolder,
   go up one level. For system dirs (System32), only stage the exe itself.
2. **Hardlink tree** — All files from app root are hardlinked into `{rootfs}\App\`.
   Zero extra disk space. Excludes match glob patterns (`*.pdb`, `**/Installer/**`).
3. **Isolated desktop** — Process runs on a separate Windows Desktop, invisible to
   the host and unable to interact with host windows.
4. **Cleanup** — Container rootfs is deleted when the app exits.

### Smart System Directory Detection

For executables in `C:\Windows\System32`, `SysWOW64`, etc., only the exe file itself
is staged (not the entire 10GB+ system directory). This handles apps like `notepad.exe`,
`mspaint.exe`, or `calc.exe` correctly.

### Programmatic API

```rust
use psroot_container::app_stage::{AppStageConfig, stage_and_run_gui, stage_and_spawn_gui};

// Simple: run and wait
let config = AppStageConfig::from_exe(r"C:\Program Files\MyApp\app.exe")?;
let exit_code = stage_and_run_gui(&config)?;

// Advanced: non-blocking with handle control
let config = AppStageConfig::from_exe(r"C:\path\app.exe")?
    .with_args(vec!["--flag".into()])
    .with_excludes(vec!["*.log".into()])
    .with_extra_dir(r"C:\plugins", "Plugins");
let (desktop, proc, rootfs) = stage_and_spawn_gui(&config)?;
// ... do stuff while app runs ...
proc.terminate();
drop(desktop);
std::fs::remove_dir_all(&rootfs).ok();
```

## Catalog File: `chrome.toml`

The resolver uses a catalog file to know how to stage Chrome:

```toml
name    = "chrome"
display = "Google Chrome"

# Probe: find Chrome on host
[[probe]]
type = "path"
glob = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

# Stage: hardlink entire Chrome dir into container
[[stage]]
op = "hardlink_tree"
src = "{shell_root}"
dst = "{cache_dir}"
exclude = ["*.pdb", "**/Installer/**"]

[[stage]]
op = "junction"
src = "{cache_dir}"
dst = "{rootfs}\\Chrome"

# ACL: container SID gets read+execute on Chrome
[[ace]]
path = "{cache_dir}"
access = "RX"
inherit = true

# Launch: from INSIDE the rootfs
[launch]
entry = "{rootfs}\\Chrome\\chrome.exe"
args = ["--no-first-run", "--user-data-dir={rootfs}\\Users\\ContainerUser\\ChromeData"]
```

## Security Model

| Layer | What It Isolates | Mechanism | What It Prevents |
|-------|-----------------|-----------|------------------|
| **Rootfs Staging** | Binary location | Hardlink into rootfs | Chrome runs from container, not host path |
| **AppContainer** | Filesystem, registry, named objects | SID-based ACL | Cannot read C:\Users\*, host files |
| **Desktop** | GUI (windows, input, messages) | `CreateDesktopW` | Cannot see/message other windows |
| **Job Object** | Resources (memory, CPU, process count) | Kernel job limits | Cannot DOS the host |
| **Environment** | Host paths leaked via env vars | Sanitization | PATH, USERPROFILE point to rootfs |

All layers are **kernel-enforced** and stack independently. Even if one is
bypassed, the others still protect.

## Limitations

- The binary content comes from host Chrome (via hardlinks) — if host Chrome
  is compromised, so is the staged copy
- Clipboard is shared within the Window Station (AppContainer blocks clipboard
  access by default)
- Audio output works (routed through session audio)
- Network access is controlled via capabilities — `internetClient` allows outbound
- The isolated desktop is session-scoped (same user can access via
  `SwitchDesktop` if they have the handle)
- GPU process shares the DWM compositor (rendering isolation is per-desktop,
  not per-GPU-context)
