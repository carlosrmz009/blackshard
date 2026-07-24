using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace BlackshardDevelopmentSetup
{
    internal sealed class SetupForm : Form
    {
        private static readonly Color Background = Color.FromArgb(14, 16, 16);
        private static readonly Color Surface = Color.FromArgb(25, 28, 28);
        private static readonly Color Muted = Color.FromArgb(145, 154, 154);
        private static readonly Color Accent = Color.FromArgb(0, 255, 90);
        private static readonly Color Failure = Color.FromArgb(255, 76, 76);

        private readonly Label statusLabel;
        private readonly Label detailLabel;
        private readonly CheckBox confirmation;
        private readonly Button installButton;
        private readonly Button openButton;
        private readonly Button copyButton;
        private readonly TextBox logBox;
        private readonly ProgressBar progress;
        private Process setupProcess;
        private bool rebootPending;
        private bool installComplete;
        private string failureDetail;

        internal SetupForm()
        {
            Text = "Blackshard VM Setup";
            ClientSize = new Size(760, 520);
            MinimumSize = new Size(776, 559);
            MaximumSize = new Size(776, 559);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Background;
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 9F);

            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 68,
                BackColor = Color.FromArgb(19, 22, 22)
            };
            Controls.Add(header);

            var mark = new Label
            {
                Text = "B",
                Font = new Font("Consolas", 20F, FontStyle.Bold),
                ForeColor = Background,
                BackColor = Accent,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(18, 16),
                Size = new Size(36, 36)
            };
            header.Controls.Add(mark);

            header.Controls.Add(new Label
            {
                Text = "BLACKSHARD // VM SETUP",
                Font = new Font("Consolas", 15F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(68, 13)
            });
            header.Controls.Add(new Label
            {
                Text = "FULL PROTECTION INSTALLER  |  DEVELOPMENT VM ONLY",
                Font = new Font("Consolas", 8.5F),
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(70, 41)
            });

            var accentLine = new Panel
            {
                BackColor = Accent,
                Height = 1,
                Dock = DockStyle.Top
            };
            Controls.Add(accentLine);
            accentLine.BringToFront();

            statusLabel = new Label
            {
                Text = "READY TO INSTALL",
                Font = new Font("Consolas", 13F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(22, 87)
            };
            Controls.Add(statusLabel);

            detailLabel = new Label
            {
                Text = "Installs the UI, LocalSystem engine, minifilter, quarantine, and real-time protection.",
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(24, 116)
            };
            Controls.Add(detailLabel);

            confirmation = new CheckBox
            {
                Text = "I confirm this is an isolated, snapshotted virtual machine with Secure Boot disabled.",
                ForeColor = Color.White,
                BackColor = Background,
                AutoSize = true,
                Location = new Point(25, 151)
            };
            confirmation.CheckedChanged += delegate { UpdateInstallButtonAvailability(); };
            Controls.Add(confirmation);

            installButton = CreateButton("INSTALL FULL PROTECTION", new Point(24, 184), new Size(225, 38), true);
            installButton.Enabled = false;
            installButton.Click += StartSetup;
            Controls.Add(installButton);
            UpdateInstallButtonAvailability();

            openButton = CreateButton("OPEN BLACKSHARD", new Point(260, 184), new Size(180, 38), false);
            openButton.Enabled = false;
            openButton.Click += OpenBlackshard;
            Controls.Add(openButton);

            copyButton = CreateButton("COPY LOG", new Point(451, 184), new Size(120, 38), false);
            copyButton.Click += delegate
            {
                if (!string.IsNullOrWhiteSpace(logBox.Text)) Clipboard.SetText(logBox.Text);
            };
            Controls.Add(copyButton);

            progress = new ProgressBar
            {
                Location = new Point(24, 235),
                Size = new Size(712, 6),
                Style = ProgressBarStyle.Blocks,
                MarqueeAnimationSpeed = 24
            };
            Controls.Add(progress);

            var logHeader = new Label
            {
                Text = "INSTALLATION ACTIVITY",
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                ForeColor = Accent,
                AutoSize = true,
                Location = new Point(22, 257)
            };
            Controls.Add(logHeader);

            logBox = new TextBox
            {
                Location = new Point(24, 282),
                Size = new Size(712, 178),
                BackColor = Surface,
                ForeColor = Color.FromArgb(210, 218, 218),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5F),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = true
            };
            Controls.Add(logBox);

            Controls.Add(new Label
            {
                Text = "Unsigned development installer | Never use on a physical or personal Windows installation",
                ForeColor = Muted,
                AutoSize = true,
                Location = new Point(24, 481)
            });

            FormClosing += OnFormClosing;
            AppendLog("Waiting for confirmation. No system changes have been made.");
        }

        private static Button CreateButton(string text, Point location, Size size, bool primary)
        {
            var button = new Button
            {
                Text = text,
                Location = location,
                Size = size,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                BackColor = primary ? Accent : Surface,
                ForeColor = primary ? Background : Color.White
            };
            button.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(65, 72, 72);
            button.FlatAppearance.BorderSize = 1;
            return button;
        }

        private void UpdateInstallButtonAvailability()
        {
            var enabled = confirmation.Checked && setupProcess == null && !rebootPending;
            installButton.Enabled = enabled;
            installButton.BackColor = enabled ? Accent : Surface;
            installButton.ForeColor = enabled ? Background : Muted;
            installButton.FlatAppearance.BorderColor = enabled ? Accent : Color.FromArgb(65, 72, 72);
        }

        private void StartSetup(object sender, EventArgs eventArgs)
        {
            if (!confirmation.Checked || setupProcess != null) return;
            rebootPending = false;
            installComplete = false;
            failureDetail = null;
            openButton.Enabled = false;
            installButton.Enabled = false;
            installButton.BackColor = Surface;
            installButton.ForeColor = Muted;
            installButton.FlatAppearance.BorderColor = Color.FromArgb(65, 72, 72);
            confirmation.Enabled = false;
            progress.Style = ProgressBarStyle.Marquee;
            SetStatus("INITIALIZING", "Validating the VM and preparing the protected installer payload.", Accent);
            AppendLog("Starting elevated Blackshard setup engine...");

            var script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vm-setup.ps1");
            if (!File.Exists(script))
            {
                FinishSetup(2, "The embedded setup script is missing.");
                return;
            }

            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var start = new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -UiMode",
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            try
            {
                setupProcess = new Process { StartInfo = start, EnableRaisingEvents = true };
                setupProcess.OutputDataReceived += delegate(object o, DataReceivedEventArgs e) { if (e.Data != null) HandleOutput(e.Data, false); };
                setupProcess.ErrorDataReceived += delegate(object o, DataReceivedEventArgs e) { if (e.Data != null) HandleOutput(e.Data, true); };
                setupProcess.Exited += delegate
                {
                    var code = setupProcess.ExitCode;
                    BeginInvoke((Action)(() => FinishSetup(code, null)));
                };
                setupProcess.Start();
                setupProcess.BeginOutputReadLine();
                setupProcess.BeginErrorReadLine();
            }
            catch (Exception error)
            {
                setupProcess = null;
                FinishSetup(2, error.Message);
            }
        }

        private void HandleOutput(string line, bool error)
        {
            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => HandleOutput(line, error)));
                return;
            }
            if (line.StartsWith("BLACKSHARD_UI:STATUS:", StringComparison.Ordinal))
            {
                var message = line.Substring("BLACKSHARD_UI:STATUS:".Length);
                SetStatus("INSTALLING", message, Accent);
                AppendLog(message);
                return;
            }
            if (line == "BLACKSHARD_UI:REBOOT_PENDING")
            {
                rebootPending = true;
                SetStatus("REBOOT SCHEDULED", "Windows will restart and setup will resume automatically.", Accent);
                AppendLog("Restart scheduled. Setup will continue as LocalSystem during boot.");
                return;
            }
            if (line == "BLACKSHARD_UI:INSTALL_COMPLETE")
            {
                installComplete = true;
                AppendLog("All components installed and verified.");
                return;
            }
            if (line.StartsWith("BLACKSHARD_UI:ERROR:", StringComparison.Ordinal))
            {
                failureDetail = line.Substring("BLACKSHARD_UI:ERROR:".Length).Trim();
                SetStatus("INSTALLATION FAILED", "The setup engine reported an error. See the activity log below.", Failure);
                AppendLog("ERROR: " + failureDetail);
                return;
            }
            AppendLog((error ? "ERROR: " : "") + line);
        }

        private void FinishSetup(int exitCode, string immediateError)
        {
            if (setupProcess != null)
            {
                setupProcess.Dispose();
                setupProcess = null;
            }
            progress.Style = ProgressBarStyle.Blocks;
            progress.Value = 0;

            if (exitCode == 0 && (installComplete || File.Exists(@"C:\Program Files\Blackshard\blackshard-ui.exe")) && !rebootPending)
            {
                SetStatus("PROTECTION ONLINE", "Installation and verification completed. Open Blackshard to begin testing.", Accent);
                openButton.Enabled = true;
                installButton.Text = "REPAIR INSTALLATION";
            }
            else if (exitCode == 0 && rebootPending)
            {
                SetStatus("REBOOT SCHEDULED", "Leave this window open; Windows will restart and setup will continue during boot.", Accent);
            }
            else
            {
                var detail = !string.IsNullOrWhiteSpace(immediateError)
                    ? immediateError
                    : !string.IsNullOrWhiteSpace(failureDetail)
                        ? "The setup engine reported an error. Review and copy the activity log below."
                        : "Setup exited with code " + exitCode + ". Review and copy the activity log below.";
                SetStatus("INSTALLATION FAILED", detail, Failure);
                AppendLog("Setup failed. Persistent logs: %TEMP%\\BlackshardVmSetup.log and C:\\ProgramData\\BlackshardDevelopmentInstaller\\setup.log");
                installButton.Text = "RETRY INSTALLATION";
            }
            confirmation.Enabled = true;
            UpdateInstallButtonAvailability();
        }

        private void SetStatus(string status, string detail, Color color)
        {
            statusLabel.Text = status;
            statusLabel.ForeColor = color;
            detailLabel.Text = detail;
        }

        private void AppendLog(string line)
        {
            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => AppendLog(line)));
                return;
            }
            logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + line + Environment.NewLine);
            logBox.SelectionStart = logBox.TextLength;
            logBox.ScrollToCaret();
        }

        private void OpenBlackshard(object sender, EventArgs eventArgs)
        {
            const string ui = @"C:\Program Files\Blackshard\blackshard-ui.exe";
            if (!File.Exists(ui))
            {
                MessageBox.Show("The installed Blackshard executable was not found.", "Blackshard VM Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", "\"" + ui + "\"") { UseShellExecute = true });
        }

        private void OnFormClosing(object sender, FormClosingEventArgs eventArgs)
        {
            if (setupProcess == null) return;
            var result = MessageBox.Show(
                "Setup is still running. Closing this window could leave installation incomplete. Close anyway?",
                "Blackshard VM Setup",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) eventArgs.Cancel = true;
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm());
        }
    }
}
