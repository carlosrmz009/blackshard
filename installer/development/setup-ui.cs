using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace blackshardDevelopmentSetup
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
            Text = "blackshard VM setup";
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
                Text = "blackshard // VM SETUP",
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

            openButton = CreateButton("OPEN blackshard", new Point(260, 184), new Size(180, 38), false);
            openButton.Enabled = false;
            openButton.Click += OpenProduct;
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
            AppendLog("Starting elevated blackshard setup engine...");

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
            if (line.StartsWith("blackshard_ui:STATUS:", StringComparison.Ordinal))
            {
                var message = line.Substring("blackshard_ui:STATUS:".Length);
                SetStatus("INSTALLING", message, Accent);
                AppendLog(message);
                return;
            }
            if (line == "blackshard_ui:REBOOT_PENDING")
            {
                rebootPending = true;
                SetStatus("REBOOT SCHEDULED", "Windows will restart and setup will resume automatically.", Accent);
                AppendLog("Restart scheduled. Setup will continue as LocalSystem during boot.");
                return;
            }
            if (line == "blackshard_ui:INSTALL_COMPLETE")
            {
                installComplete = true;
                AppendLog("All components installed and verified.");
                return;
            }
            if (line.StartsWith("blackshard_ui:ERROR:", StringComparison.Ordinal))
            {
                failureDetail = line.Substring("blackshard_ui:ERROR:".Length).Trim();
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

            if (exitCode == 0 && (installComplete || File.Exists(@"C:\Program Files\blackshard\blackshard-ui.exe")) && !rebootPending)
            {
                SetStatus("PROTECTION ONLINE", "Installation and verification completed.", Accent);
                AppendLog("Opening the blackshard completion experience.");
                LaunchCompletionExperience();
                Close();
                return;
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
                AppendLog("Setup failed. Persistent logs: %TEMP%\\blackshard-vm-setup.log and C:\\ProgramData\\blackshard-development-installer\\setup.log");
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

        private static void LaunchCompletionExperience()
        {
            var script = @"C:\ProgramData\blackshard-development-installer\vm-setup.ps1";
            if (!File.Exists(script)) return;

            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            Process.Start(new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -CompleteForUser",
                WorkingDirectory = Path.GetDirectoryName(script),
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }

        private void OpenProduct(object sender, EventArgs eventArgs)
        {
            const string ui = @"C:\Program Files\blackshard\blackshard-ui.exe";
            if (!File.Exists(ui))
            {
                MessageBox.Show("The installed blackshard executable was not found.", "blackshard VM setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            Process.Start(new ProcessStartInfo("explorer.exe", "\"" + ui + "\"") { UseShellExecute = true });
        }

        private void OnFormClosing(object sender, FormClosingEventArgs eventArgs)
        {
            if (setupProcess == null) return;
            var result = MessageBox.Show(
                "Setup is still running. Closing this window could leave installation incomplete. Close anyway?",
                "blackshard VM setup",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) eventArgs.Cancel = true;
        }
    }

    internal sealed class RingProgress : Control
    {
        private int progressValue;
        private Color ringColor = Color.Yellow;

        internal int ProgressValue
        {
            get { return progressValue; }
            set
            {
                progressValue = Math.Max(0, Math.Min(100, value));
                Invalidate();
            }
        }

        internal Color RingColor
        {
            get { return ringColor; }
            set
            {
                ringColor = value;
                Invalidate();
            }
        }

        internal RingProgress()
        {
            DoubleBuffered = true;
            BackColor = Color.Black;
            ForeColor = Color.White;
            Size = new Size(330, 330);
        }

        protected override void OnPaint(PaintEventArgs eventArgs)
        {
            base.OnPaint(eventArgs);
            eventArgs.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var inset = 20;
            var diameter = Math.Min(ClientSize.Width, ClientSize.Height) - inset * 2;
            var bounds = new Rectangle(inset, inset, diameter, diameter);
            using (var track = new Pen(Color.FromArgb(35, 35, 35), 18F))
            using (var ring = new Pen(ringColor, 18F))
            using (var font = FontResolver.CreateDisplay(48F, FontStyle.Regular))
            using (var brush = new SolidBrush(ForeColor))
            {
                track.StartCap = LineCap.Round;
                track.EndCap = LineCap.Round;
                ring.StartCap = LineCap.Round;
                ring.EndCap = LineCap.Round;
                eventArgs.Graphics.DrawArc(track, bounds, -90F, 360F);
                if (progressValue > 0)
                {
                    eventArgs.Graphics.DrawArc(ring, bounds, -90F, 360F * progressValue / 100F);
                }
                var text = progressValue + "%";
                var measured = eventArgs.Graphics.MeasureString(text, font);
                eventArgs.Graphics.DrawString(
                    text,
                    font,
                    brush,
                    (ClientSize.Width - measured.Width) / 2F,
                    (ClientSize.Height - measured.Height) / 2F
                );
            }
        }
    }

    internal static class FontResolver
    {
        internal static Font CreateDisplay(float size, FontStyle style)
        {
            return Create("Helvetica Now Display", "Arial", size, style);
        }

        internal static Font CreateMono(float size, FontStyle style)
        {
            return Create("JetBrains Mono", "Consolas", size, style);
        }

        private static Font Create(string preferred, string fallback, float size, FontStyle style)
        {
            var font = new Font(preferred, size, style, GraphicsUnit.Point);
            if (!font.Name.Equals(preferred, StringComparison.OrdinalIgnoreCase))
            {
                font.Dispose();
                font = new Font(fallback, size, style, GraphicsUnit.Point);
            }
            return font;
        }
    }

    internal sealed class ResumeMonitorForm : Form
    {
        private static readonly Color Background = Color.Black;
        private static readonly Color Surface = Color.FromArgb(25, 25, 25);
        private static readonly Color Accent = Color.Yellow;
        private static readonly Color Failure = Color.FromArgb(255, 55, 55);
        private static readonly string StageRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "blackshard-development-installer"
        );
        private static readonly string LogPath = Path.Combine(StageRoot, "setup.log");
        private static readonly string SuccessPath = Path.Combine(StageRoot, "installed.txt");
        private static readonly string FailurePath = Path.Combine(StageRoot, "failed.txt");

        private readonly RingProgress ring;
        private readonly Label stateLabel;
        private readonly TextBox logBox;
        private readonly Button copyButton;
        private readonly Button openLogButton;
        private readonly Timer monitorTimer;
        private readonly DateTime startedAt;
        private string displayedLog = "";
        private bool terminal;

        internal ResumeMonitorForm()
        {
            Text = "blackshard installation";
            BackColor = Background;
            ForeColor = Color.White;
            FormBorderStyle = FormBorderStyle.None;
            WindowState = FormWindowState.Maximized;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            KeyPreview = true;
            Padding = new Padding(38);

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 2,
                RowCount = 1
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48F));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52F));
            Controls.Add(layout);

            var left = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(60, 5, 55, 5)
            };
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 23F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 22F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 47F));
            left.RowStyles.Add(new RowStyle(SizeType.Percent, 8F));
            layout.Controls.Add(left, 0, 0);

            var title = new Label
            {
                Text = "installing",
                Dock = DockStyle.Fill,
                ForeColor = Accent,
                TextAlign = ContentAlignment.MiddleLeft,
                Font = FontResolver.CreateDisplay(76F, FontStyle.Regular)
            };
            left.Controls.Add(title, 0, 0);

            var brand = BuildBrand();
            left.Controls.Add(brand, 0, 1);

            ring = new RingProgress
            {
                Dock = DockStyle.Fill,
                ProgressValue = 5,
                RingColor = Accent,
                Margin = new Padding(40, 5, 40, 5)
            };
            left.Controls.Add(ring, 0, 2);

            stateLabel = new Label
            {
                Text = "Waiting for the installation worker...",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = FontResolver.CreateDisplay(14F, FontStyle.Regular)
            };
            left.Controls.Add(stateLabel, 0, 3);

            var rightShell = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                Padding = new Padding(28),
                Margin = new Padding(25, 22, 32, 22)
            };
            layout.Controls.Add(rightShell, 1, 0);

            var right = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                ColumnCount = 1,
                RowCount = 3
            };
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 42F));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 54F));
            rightShell.Controls.Add(right);

            right.Controls.Add(new Label
            {
                Text = "live installation log",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                Font = FontResolver.CreateMono(13F, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft
            }, 0, 0);

            logBox = new TextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                ForeColor = Color.White,
                BorderStyle = BorderStyle.None,
                Font = FontResolver.CreateMono(10.5F, FontStyle.Regular),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = true
            };
            right.Controls.Add(logBox, 0, 1);

            var actions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Surface,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 10, 0, 0)
            };
            copyButton = CreateMonitorButton("copy log");
            copyButton.Click += delegate
            {
                if (!string.IsNullOrWhiteSpace(logBox.Text))
                {
                    Clipboard.SetText(logBox.Text);
                }
            };
            actions.Controls.Add(copyButton);

            openLogButton = CreateMonitorButton("open log");
            openLogButton.Click += delegate
            {
                if (File.Exists(LogPath))
                {
                    Process.Start(new ProcessStartInfo("notepad.exe", "\"" + LogPath + "\"") { UseShellExecute = true });
                }
            };
            actions.Controls.Add(openLogButton);

            var closeButton = CreateMonitorButton("close");
            closeButton.Click += delegate { Close(); };
            actions.Controls.Add(closeButton);
            right.Controls.Add(actions, 0, 2);

            FormClosing += OnMonitorClosing;
            KeyDown += delegate(object sender, KeyEventArgs eventArgs)
            {
                if (eventArgs.KeyCode == Keys.Escape)
                {
                    Close();
                }
            };

            startedAt = DateTime.UtcNow;
            monitorTimer = new Timer { Interval = 500 };
            monitorTimer.Tick += MonitorInstallation;
            monitorTimer.Start();
            MonitorInstallation(this, EventArgs.Empty);
        }

        private static Control BuildBrand()
        {
            var brand = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 2,
                RowCount = 1
            };
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150F));
            brand.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            var logoPath = Path.Combine(StageRoot, "logo.png");
            if (File.Exists(logoPath))
            {
                try
                {
                    using (var source = Image.FromFile(logoPath))
                    {
                        brand.Controls.Add(new PictureBox
                        {
                            Image = new Bitmap(source),
                            Dock = DockStyle.Fill,
                            SizeMode = PictureBoxSizeMode.Zoom,
                            BackColor = Background,
                            Margin = new Padding(0, 0, 20, 0)
                        }, 0, 0);
                    }
                }
                catch
                {
                }
            }

            var text = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Background,
                ColumnCount = 1,
                RowCount = 2
            };
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 62F));
            text.RowStyles.Add(new RowStyle(SizeType.Percent, 38F));
            text.Controls.Add(new Label
            {
                Text = "blackshard",
                Dock = DockStyle.Fill,
                ForeColor = Color.White,
                TextAlign = ContentAlignment.BottomLeft,
                Font = FontResolver.CreateMono(34F, FontStyle.Bold)
            }, 0, 0);
            text.Controls.Add(new Label
            {
                Text = "prototype",
                Dock = DockStyle.Fill,
                ForeColor = Failure,
                TextAlign = ContentAlignment.TopLeft,
                Font = FontResolver.CreateMono(20F, FontStyle.Bold)
            }, 0, 1);
            brand.Controls.Add(text, 1, 0);
            return brand;
        }

        private static Button CreateMonitorButton(string text)
        {
            var button = new Button
            {
                Text = text,
                AutoSize = true,
                Height = 34,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(35, 35, 35),
                ForeColor = Color.White,
                Font = FontResolver.CreateMono(9F, FontStyle.Regular),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 10, 0)
            };
            button.FlatAppearance.BorderColor = Color.FromArgb(70, 70, 70);
            return button;
        }

        private void MonitorInstallation(object sender, EventArgs eventArgs)
        {
            if (terminal)
            {
                return;
            }

            var log = ReadSharedText(LogPath);
            if (log != displayedLog)
            {
                displayedLog = log;
                var visible = log.Length > 60000 ? log.Substring(log.Length - 60000) : log;
                logBox.Text = visible;
                logBox.SelectionStart = logBox.TextLength;
                logBox.ScrollToCaret();
                ApplyLatestProgress(log);
            }

            if (File.Exists(FailurePath))
            {
                ShowFailure(ReadSharedText(FailurePath));
                return;
            }
            if (File.Exists(SuccessPath))
            {
                ShowSuccess();
                return;
            }
            if ((DateTime.UtcNow - startedAt).TotalMinutes >= 16)
            {
                ShowFailure("The installation task did not produce a completion marker within 16 minutes.");
            }
        }

        private void ApplyLatestProgress(string log)
        {
            var matches = Regex.Matches(
                log,
                @"blackshard_ui:PROGRESS:(\d{1,3}):([^\r\n]+)",
                RegexOptions.CultureInvariant
            );
            if (matches.Count > 0)
            {
                var match = matches[matches.Count - 1];
                int value;
                if (int.TryParse(match.Groups[1].Value, out value))
                {
                    ring.ProgressValue = value;
                }
                stateLabel.Text = match.Groups[2].Value.Trim();
                return;
            }

            var statuses = Regex.Matches(
                log,
                @"blackshard_ui:STATUS:([^\r\n]+)",
                RegexOptions.CultureInvariant
            );
            if (statuses.Count > 0)
            {
                stateLabel.Text = statuses[statuses.Count - 1].Groups[1].Value.Trim();
            }
        }

        private void ShowFailure(string detail)
        {
            terminal = true;
            monitorTimer.Stop();
            ring.RingColor = Failure;
            stateLabel.ForeColor = Failure;
            stateLabel.Text = "Installation failed. The complete diagnostic log is shown on the right.";
            if (!string.IsNullOrWhiteSpace(detail) && displayedLog.IndexOf(detail, StringComparison.Ordinal) < 0)
            {
                logBox.AppendText(Environment.NewLine + Environment.NewLine + detail.Trim());
                logBox.SelectionStart = logBox.TextLength;
                logBox.ScrollToCaret();
            }
        }

        private void ShowSuccess()
        {
            terminal = true;
            monitorTimer.Stop();
            ring.ProgressValue = 100;
            ring.RingColor = Accent;
            stateLabel.ForeColor = Color.White;
            stateLabel.Text = "Installation verified. Opening the blackshard welcome screen...";
            var completionTimer = new Timer { Interval = 900 };
            completionTimer.Tick += delegate
            {
                completionTimer.Stop();
                LaunchCompletionExperience();
                Close();
            };
            completionTimer.Start();
        }

        private static string ReadSharedText(string path)
        {
            if (!File.Exists(path))
            {
                return "";
            }
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (IOException error)
            {
                return "Waiting for the installation log..." + Environment.NewLine + error.Message;
            }
            catch (UnauthorizedAccessException error)
            {
                return "The installation log is not readable yet." + Environment.NewLine + error.Message;
            }
        }

        private static void LaunchCompletionExperience()
        {
            var script = Path.Combine(StageRoot, "vm-setup.ps1");
            if (!File.Exists(script))
            {
                return;
            }
            var powerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            Process.Start(new ProcessStartInfo
            {
                FileName = powerShell,
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\" -CompleteForUser",
                WorkingDirectory = StageRoot,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }

        private void OnMonitorClosing(object sender, FormClosingEventArgs eventArgs)
        {
            if (terminal)
            {
                return;
            }
            var result = MessageBox.Show(
                "blackshard is still installing in the background. Close the progress window?",
                "blackshard VM setup",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );
            if (result != DialogResult.Yes)
            {
                eventArgs.Cancel = true;
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length == 1 && args[0].Equals("--resume-monitor", StringComparison.OrdinalIgnoreCase))
            {
                Application.Run(new ResumeMonitorForm());
            }
            else
            {
                Application.Run(new SetupForm());
            }
        }
    }
}
