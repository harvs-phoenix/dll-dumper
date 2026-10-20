using System.Diagnostics;
using DllDumper.Core;

namespace DllDumper;

public sealed class MainForm : Form
{
    // =========================================================================
    // theme
    // =========================================================================
    private static readonly Color CBack = Color.FromArgb(23, 23, 26);
    private static readonly Color CPanel = Color.FromArgb(31, 31, 36);
    private static readonly Color CField = Color.FromArgb(38, 38, 45);
    private static readonly Color CDark = Color.FromArgb(26, 26, 30);
    private static readonly Color CText = Color.FromArgb(224, 224, 228);
    private static readonly Color CDim = Color.FromArgb(138, 138, 147);
    private static readonly Color CRed = Color.FromArgb(226, 55, 63);
    private static readonly Color CRedDark = Color.FromArgb(110, 30, 36);
    private static readonly Color COk = Color.FromArgb(120, 220, 140);
    private static readonly Color CLine = Color.FromArgb(62, 62, 70);

    private static readonly Font FTitle = new("Segoe UI", 15f, FontStyle.Bold);
    private static readonly Font FSub = new("Segoe UI", 8.5f);
    private static readonly Font FUi = new("Segoe UI", 9f);
    private static readonly Font FData = new("Consolas", 9f);

    private readonly record struct MonoRow(string Src, string Kind, string Name, string Detail);

    private const int MonoDisplayCap = 5000;
    private const int MonoBuildCap = 50_000;
    private const int RecordViewCap = 10_000;

    // =========================================================================
    // controls
    // =========================================================================
    private Label _titleLabel = null!, _subLabel = null!, _recLabel = null!;
    private Button _bigRecordBtn = null!, _refreshBtn = null!, _advToggleBtn = null!;
    private TextBox _filterBox = null!;
    private ListView _procList = null!;
    private Label _targetLabel = null!;

    // simple view --------------------------------------------------------------
    private Panel _viewHost = null!, _advPanel = null!;
    private TableLayoutPanel _simplePanel = null!;
    private Label _simpleStatus = null!;
    private Label _cardDllTitle = null!, _cardDllBody = null!;
    private Label _cardMemTitle = null!, _cardMemBody = null!;
    private Label _cardMonoTitle = null!, _cardMonoBody = null!;
    private ComboBox _simpleModeBox = null!, _recoverBox = null!;
    private TextBox _simplePayloadBox = null!;
    private Button _simpleBrowseBtn = null!, _simpleInjectBtn = null!, _recoverBtn = null!;

    // advanced view -------------------------------------------------------------
    private ComboBox _modeBox = null!;
    private TextBox _payloadBox = null!, _nsBox = null!, _clsBox = null!;
    private TextBox _methodBox = null!, _paramBox = null!;
    private CheckBox _execBox = null!;
    private Label _labelEntry = null!, _hintLabel = null!;
    private Button _browseBtn = null!, _injectBtn = null!;

    private TabControl _tabs = null!;
    private TextBox _searchBox = null!;
    private Button _searchBtn = null!, _saveBtn = null!;
    private Label _monoInfo = null!, _memInfo = null!, _filesInfo = null!;
    private Label _recInfo = null!, _injInfo = null!;
    private ListView _monoList = null!, _memList = null!, _filesList = null!;
    private ListView _recList = null!, _injList = null!;
    private TextBox _injDetail = null!;
    private Label _statusLabel = null!;
    private readonly ToolTip _tip = new();

    // =========================================================================
    // state
    // =========================================================================
    private readonly Recorder _rec = new();
    private ProcessInspector? _proc;
    private MonoRuntime? _runtime;
    private readonly List<AssemblyScan> _assemblies = new();
    private HashSet<string> _scannedPaths = new(StringComparer.OrdinalIgnoreCase);
    private List<ModuleInfo> _modules = new();
    private List<MemoryRegion> _regions = new();

    private System.Windows.Forms.Timer _tickTimer = null!;
    private System.Windows.Forms.Timer _searchTimer = null!;
    private System.Windows.Forms.Timer _blinkTimer = null!;

    private bool _capturing, _injecting, _refreshing, _suppressProcSelect;
    private bool _syncing, _recovering, _showSimple = true;
    private readonly Dictionary<string, InjectItem> _lastByMode = new();
    private List<(string Name, int Pid, string Title, long Ws)> _processes = new();
    private int _version, _searchVersion;
    private bool _haveBaseline;
    private int _lastFiles = -1, _lastRegions = -1, _lastRecoverCount = -1;
    private int _injTotal, _injOk;
    private readonly string[] _startupArgs;

    // =========================================================================
    // construction
    // =========================================================================
    public MainForm(string[]? startupArgs = null)
    {
        _startupArgs = startupArgs ?? Array.Empty<string>();
        Text = "Dll Dumper — mono recorder & injector";
        ClientSize = new Size(1440, 900);
        MinimumSize = new Size(1280, 760);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = CBack;
        ForeColor = CText;
        Font = FUi;
        KeyPreview = true;
        AllowDrop = true;

        BuildLayout();

        _rec.ItemAdded += OnRecordAdded;
        _rec.StateChanged += UpdateRecordUi;

        _tickTimer = new System.Windows.Forms.Timer { Interval = 4000 };
        _tickTimer.Tick += async (_, _) => { if (_rec.IsRecording && !_capturing) await RunCaptureAsync(); };

        _searchTimer = new System.Windows.Forms.Timer { Interval = 400 };
        _searchTimer.Tick += (_, _) => { _searchTimer.Stop(); ApplyMonoSearch(); };

        _blinkTimer = new System.Windows.Forms.Timer { Interval = 500 };
        _blinkTimer.Tick += (_, _) =>
        {
            if (_rec.IsRecording)
            {
                _recLabel.ForeColor = _recLabel.ForeColor == CRed ? CRedDark : CRed;
                _bigRecordBtn.Text = $"■   S T O P   ·   {_rec.Elapsed:mm\\:ss}";
                _simpleStatus.ForeColor = CRed;
                _simpleStatus.Text =
                    $"● recording {_proc?.Name} · {_rec.Elapsed:hh\\:mm\\:ss} · " +
                    $"{_rec.Items.Count:N0} items · {_rec.Injections.Count} injections";
            }
            else
            {
                _recLabel.ForeColor = CDim;
            }
        };
        _blinkTimer.Start();

        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy;
        };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
            {
                _payloadBox.Text = files[0];
                SetStatus($"payload set → {files[0]}  (mode: {_modeBox.SelectedItem})");
            }
        };

        Load += async (_, _) =>
        {
            await RefreshProcessesAsync();
            await SelectFromArgsAsync();
            SelectTabFromArgs();
        };
        FormClosing += (_, _) => { _tickTimer.Stop(); _searchTimer.Stop(); _blinkTimer.Stop(); _proc?.Dispose(); };
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.F5) { e.Handled = true; _ = RefreshProcessesAsync(); }
        base.OnKeyDown(e);
    }

    // =========================================================================
    // layout
    // =========================================================================
    private void BuildLayout()
    {
        // ---------- header ----------
        _titleLabel = new Label
        {
            Text = "DLL DUMPER",
            Font = FTitle,
            ForeColor = CRed,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        _subLabel = new Label
        {
            Text = "pick a running process · record its mono, memory & files · inject DLL / memory / mono payloads",
            Font = FSub,
            ForeColor = CDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.TopLeft,
        };

        var titleTable = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
        titleTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        titleTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        titleTable.Controls.Add(_titleLabel, 0, 0);
        titleTable.Controls.Add(_subLabel, 0, 1);

        _recLabel = new Label
        {
            Text = "○ IDLE",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = CDim,
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleRight,
            Margin = new Padding(0, 6, 12, 0),
        };
        _advToggleBtn = MakeButton("Advanced ▸");
        _advToggleBtn.Margin = new Padding(0, 2, 0, 2);

        var rightTable = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        rightTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        rightTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        rightTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        rightTable.Controls.Add(_recLabel, 0, 0);
        rightTable.Controls.Add(_advToggleBtn, 1, 0);

        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Padding = new Padding(14, 6, 14, 4) };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        // NOTE: always add an explicit RowStyle — a style-less row can size itself
        // past the table height and silently clip its children (see BuildLayout).
        header.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        header.Controls.Add(titleTable, 0, 0);
        header.Controls.Add(rightTable, 1, 0);

        // ---------- status bar ----------
        _statusLabel = new Label
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = CDim,
            Font = FSub,
            Padding = new Padding(14, 0, 0, 0),
            Text = "Ready — select a process from the list, then press ● Record.",
        };
        var statusPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 1, BackColor = Color.FromArgb(18, 18, 21), Padding = Padding.Empty };
        statusPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusPanel.Controls.Add(_statusLabel, 0, 0);

        // ---------- left: process list ----------
        _filterBox = MakeTextBox();
        _filterBox.Text = "";
        _refreshBtn = MakeButton("Refresh");

        var filterPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
        filterPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        filterPanel.Controls.Add(_filterBox, 0, 0);
        filterPanel.Controls.Add(_refreshBtn, 1, 0);

        _procList = MakeListView(("Name", 118), ("PID", 62), ("Window", 160), ("Mem", 74));
        _targetLabel = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = CDim,
            Font = FSub,
            TextAlign = ContentAlignment.TopLeft,
            AutoEllipsis = true,
            Padding = new Padding(3, 5, 3, 0),
            Text = "no process selected",
        };

        var left = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(10, 8, 8, 8) };
        left.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        left.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        left.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
        left.Controls.Add(filterPanel, 0, 0);
        left.Controls.Add(_procList, 0, 1);
        left.Controls.Add(_targetLabel, 0, 2);

        // ---------- right: simple view (default) or advanced view ----------
        _viewHost = new Panel { Dock = DockStyle.Fill, BackColor = CPanel, Margin = Padding.Empty, Padding = Padding.Empty };
        BuildAdvancedPanel();
        BuildSimplePanel();
        ShowView(simple: true);

        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 310));
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        body.Controls.Add(left, 0, 0);
        body.Controls.Add(_viewHost, 1, 0);

        // ---------- root ----------
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = Padding.Empty, Margin = Padding.Empty };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 66));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        root.Controls.Add(header, 0, 0);
        root.Controls.Add(body, 0, 1);
        root.Controls.Add(statusPanel, 0, 2);
        Controls.Add(root);

        // ---------- wiring ----------
        _procList.SelectedIndexChanged += (_, _) => OnProcessSelected();
        _refreshBtn.Click += async (_, _) => await RefreshProcessesAsync();
        _filterBox.TextChanged += (_, _) => ApplyProcessFilter();
        _bigRecordBtn.Click += async (_, _) => { if (_rec.IsRecording) await StopAsync(); else await RecordAsync(); };
        _advToggleBtn.Click += (_, _) => ShowView(!_showSimple);
        _browseBtn.Click += (_, _) => BrowsePayload();
        _simpleBrowseBtn.Click += (_, _) => BrowsePayload();
        _modeBox.SelectedIndexChanged += (_, _) => { UpdateModeUi(); SyncFromAdvanced(); };
        _simpleModeBox.SelectedIndexChanged += (_, _) => SyncFromSimple();
        _payloadBox.TextChanged += (_, _) => { if (!_syncing) { _syncing = true; _simplePayloadBox.Text = _payloadBox.Text; _syncing = false; } };
        _simplePayloadBox.TextChanged += (_, _) => { if (!_syncing) { _syncing = true; _payloadBox.Text = _simplePayloadBox.Text; _syncing = false; } };
        _injectBtn.Click += async (_, _) => await InjectAsync();
        _simpleInjectBtn.Click += async (_, _) => await InjectAsync();
        _recoverBtn.Click += async (_, _) => await RecoverModuleAsync();
        void OpenInjected() { ShowView(false); SelectTabByName("Injected"); }
        _cardDllTitle.Click += (_, _) => OpenInjected(); _cardDllBody.Click += (_, _) => OpenInjected();
        _cardMemTitle.Click += (_, _) => OpenInjected(); _cardMemBody.Click += (_, _) => OpenInjected();
        _cardMonoTitle.Click += (_, _) => OpenInjected(); _cardMonoBody.Click += (_, _) => OpenInjected();
        _searchBox.TextChanged += (_, _) => { _searchTimer.Stop(); _searchTimer.Start(); };
        _searchBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; _searchTimer.Stop(); ApplyMonoSearch(); }
        };
        _searchBtn.Click += (_, _) => { _searchTimer.Stop(); ApplyMonoSearch(); };
        _injList.SelectedIndexChanged += (_, _) =>
        {
            if (_injList.SelectedItems.Count > 0 && _injList.SelectedItems[0].Tag is InjectItem item)
                _injDetail.Text = string.Join(Environment.NewLine, item.Steps);
        };
        _saveBtn.Click += (_, _) => SaveReport();

        _tip.SetToolTip(_modeBox, "DLL = LoadLibraryW · Memory = raw bytes in a new region · Mono = open assembly + invoke a static method inside the runtime");
        _tip.SetToolTip(_payloadBox, "Payload file — drag & drop a file anywhere on this window to set it");
        _tip.SetToolTip(_browseBtn, "Browse for a payload");
        _tip.SetToolTip(_labelEntry, "Mono mode only: the entry point inside the payload dll");
        _tip.SetToolTip(_nsBox, "Namespace of the entry type (leave empty for the global namespace)");
        _tip.SetToolTip(_clsBox, "Class name containing the static entry method");
        _tip.SetToolTip(_methodBox, "Static method to invoke, e.g. Load");
        _tip.SetToolTip(_paramBox, "Parameter count — leave empty to search the method list automatically");
        _tip.SetToolTip(_execBox, "Memory mode: run the written bytes as a remote thread");
        _tip.SetToolTip(_injectBtn, "Inject into the selected process (Ctrl+drag payload also works)");
        _tip.SetToolTip(_searchBox, "Search assemblies, types, methods and runtime exports");
        _tip.SetToolTip(_bigRecordBtn, "Record / stop a session — everything the target does is logged (F5 refreshes the process list)");
        _tip.SetToolTip(_simpleInjectBtn, "Inject the payload into the selected process (drag & drop a file onto this window to set it)");
        _tip.SetToolTip(_recoverBtn, "Read the module straight out of the target's memory and save it to disk");
        _tip.SetToolTip(_recoverBox, "Modules loaded in the target — a dll you just injected shows up here");
        _tip.SetToolTip(_advToggleBtn, "Switch between this simple view and the advanced tabs");
        _tip.SetToolTip(_cardMonoBody, "mono injection results — click to open the Injected tab");

        UpdateModeUi();
        UpdateButtons();
    }

    private Control BuildInjectPanel()
    {
        _modeBox = new ComboBox
        {
            Dock = DockStyle.Fill,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = CField,
            ForeColor = CText,
            FlatStyle = FlatStyle.Flat,
            Font = FUi,
            Margin = Padding.Empty,
        };
        _modeBox.Items.AddRange(new object[] { "DLL", "Memory", "Mono" });
        _modeBox.SelectedIndex = 0;

        _payloadBox = MakeTextBox();
        _browseBtn = MakeButton("Browse…");

        var row0 = RowPanel(
            new ColumnStyle(SizeType.Absolute, 118),
            new ColumnStyle(SizeType.Percent, 100),
            new ColumnStyle(SizeType.Absolute, 92));
        row0.Controls.Add(_modeBox, 0, 0);
        row0.Controls.Add(_payloadBox, 1, 0);
        row0.Controls.Add(_browseBtn, 2, 0);

        _labelEntry = new Label
        {
            Text = "Mono entry:",
            Dock = DockStyle.Fill,
            ForeColor = CDim,
            TextAlign = ContentAlignment.MiddleRight,
            Margin = new Padding(0, 0, 6, 0),
        };
        _nsBox = MakeTextBox();
        _clsBox = MakeTextBox();
        _methodBox = MakeTextBox();
        _paramBox = MakeTextBox();
        _execBox = new CheckBox
        {
            Text = "Execute after write",
            Checked = true,
            Dock = DockStyle.Fill,
            ForeColor = CText,
            Margin = new Padding(6, 0, 0, 0),
        };

        var row1 = RowPanel(
            new ColumnStyle(SizeType.Absolute, 118),
            new ColumnStyle(SizeType.Absolute, 175),
            new ColumnStyle(SizeType.Absolute, 175),
            new ColumnStyle(SizeType.Absolute, 175),
            new ColumnStyle(SizeType.Absolute, 74),
            new ColumnStyle(SizeType.Percent, 100));
        row1.Controls.Add(_labelEntry, 0, 0);
        row1.Controls.Add(_nsBox, 1, 0);
        row1.Controls.Add(_clsBox, 2, 0);
        row1.Controls.Add(_methodBox, 3, 0);
        row1.Controls.Add(_paramBox, 4, 0);
        row1.Controls.Add(_execBox, 5, 0);

        _hintLabel = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = CDim,
            Font = FSub,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
        };
        _injectBtn = AccentButton("Inject ▶");

        var row2 = RowPanel(
            new ColumnStyle(SizeType.Percent, 100),
            new ColumnStyle(SizeType.Absolute, 140));
        row2.Controls.Add(_hintLabel, 0, 0);
        row2.Controls.Add(_injectBtn, 1, 0);

        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(2, 4, 2, 4),
            Margin = Padding.Empty,
        };
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33f));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33f));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.34f));
        panel.Controls.Add(row0, 0, 0);
        panel.Controls.Add(row1, 0, 1);
        panel.Controls.Add(row2, 0, 2);
        return panel;
    }

    // =========================================================================
    // simple view (default)
    // =========================================================================
    private void BuildAdvancedPanel()
    {
        var adv = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(6, 8, 10, 8) };
        adv.RowStyles.Add(new RowStyle(SizeType.Absolute, 116));
        adv.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        adv.Controls.Add(BuildInjectPanel(), 0, 0);
        BuildTabs();
        adv.Controls.Add(_tabs, 0, 1);
        _advPanel = adv;
    }

    private void BuildSimplePanel()
    {
        // --- one big record / stop button ---
        _bigRecordBtn = new Button
        {
            Text = "●  R E C O R D",
            Dock = DockStyle.Fill,
            FlatStyle = FlatStyle.Flat,
            BackColor = CRedDark,
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 16f, FontStyle.Bold),
            Cursor = Cursors.Hand,
            Margin = Padding.Empty,
            UseVisualStyleBackColor = false,
        };
        _bigRecordBtn.FlatAppearance.BorderColor = CRed;
        _bigRecordBtn.FlatAppearance.BorderSize = 2;
        _bigRecordBtn.FlatAppearance.MouseOverBackColor = Color.FromArgb(140, 36, 43);
        _bigRecordBtn.FlatAppearance.MouseDownBackColor = Color.FromArgb(90, 24, 30);

        _simpleStatus = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = CDim,
            Font = FSub,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            Padding = new Padding(2, 0, 0, 0),
            Text = "pick a process on the left, then hit RECORD",
        };

        // --- "has anything been injected?" cards ---
        _cardDllTitle = CardTitle("DLL");
        _cardDllBody = CardBody();
        var dllCard = MakeCard(_cardDllTitle, _cardDllBody);
        _cardMemTitle = CardTitle("MEMORY");
        _cardMemBody = CardBody();
        var memCard = MakeCard(_cardMemTitle, _cardMemBody);
        _cardMonoTitle = CardTitle("MONO ★", accent: true);
        _cardMonoBody = CardBody("— no mono injection yet —\npick a managed dll below, hit Inject ▶");
        var monoCard = MakeCard(_cardMonoTitle, _cardMonoBody);

        var cards = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
        cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 31));
        cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 31));
        cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
        cards.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        cards.Controls.Add(dllCard, 0, 0);
        cards.Controls.Add(memCard, 1, 0);
        cards.Controls.Add(monoCard, 2, 0);

        // --- inject row ---
        _simpleModeBox = new ComboBox
        {
            Dock = DockStyle.Fill,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = CField,
            ForeColor = CText,
            FlatStyle = FlatStyle.Flat,
            Font = FUi,
            Margin = Padding.Empty,
        };
        _simpleModeBox.Items.AddRange(new object[] { "DLL", "Memory", "Mono" });
        _simpleModeBox.SelectedIndex = 0;
        _simplePayloadBox = MakeTextBox();
        _simpleBrowseBtn = MakeButton("Browse…");
        _simpleInjectBtn = AccentButton("Inject ▶");

        var injectRow = RowPanel(
            new ColumnStyle(SizeType.Absolute, 118),
            new ColumnStyle(SizeType.Percent, 100),
            new ColumnStyle(SizeType.Absolute, 92),
            new ColumnStyle(SizeType.Absolute, 130));
        injectRow.Controls.Add(_simpleModeBox, 0, 0);
        injectRow.Controls.Add(_simplePayloadBox, 1, 0);
        injectRow.Controls.Add(_simpleBrowseBtn, 2, 0);
        injectRow.Controls.Add(_simpleInjectBtn, 3, 0);

        // --- recover row ---
        var recoverLabel = new Label
        {
            Text = "recover:",
            Dock = DockStyle.Fill,
            ForeColor = CDim,
            TextAlign = ContentAlignment.MiddleRight,
            Margin = new Padding(0, 0, 6, 0),
        };
        _recoverBox = new ComboBox
        {
            Dock = DockStyle.Fill,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = CField,
            ForeColor = CText,
            FlatStyle = FlatStyle.Flat,
            Font = FData,
            Margin = Padding.Empty,
        };
        _recoverBtn = MakeButton("Recover ▶");
        var recoverRow = RowPanel(
            new ColumnStyle(SizeType.Absolute, 118),
            new ColumnStyle(SizeType.Percent, 100),
            new ColumnStyle(SizeType.Absolute, 130));
        recoverRow.Controls.Add(recoverLabel, 0, 0);
        recoverRow.Controls.Add(_recoverBox, 1, 0);
        recoverRow.Controls.Add(_recoverBtn, 2, 0);

        var p = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(10, 10, 12, 10),
            Margin = Padding.Empty,
            BackColor = CPanel,
        };
        p.RowStyles.Add(new RowStyle(SizeType.Absolute, 86));
        p.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        p.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        p.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        p.Controls.Add(_bigRecordBtn, 0, 0);
        p.Controls.Add(_simpleStatus, 0, 1);
        p.Controls.Add(cards, 0, 2);
        p.Controls.Add(injectRow, 0, 3);
        p.Controls.Add(recoverRow, 0, 4);
        _simplePanel = p;
        UpdateInjectCards();
    }

    private static Label CardTitle(string text, bool accent = false) => new()
    {
        Text = text,
        Dock = DockStyle.Top,
        Height = 22,
        Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        ForeColor = accent ? CRed : CText,
    };

    private static Label CardBody(string placeholder = "— nothing injected yet —") => new()
    {
        Dock = DockStyle.Fill,
        Font = FSub,
        ForeColor = CDim,
        TextAlign = ContentAlignment.TopLeft,
        Text = placeholder,
    };

    private Panel MakeCard(Label title, Label body)
    {
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = CDark,
            Margin = new Padding(0, 0, 8, 0),
            Padding = new Padding(10, 8, 10, 8),
        };
        card.Controls.Add(body);
        card.Controls.Add(title);
        card.Paint += (_, e) =>
        {
            using var pen = new Pen(CLine);
            e.Graphics.DrawRectangle(pen, 0, 0, card.ClientSize.Width - 1, card.ClientSize.Height - 1);
        };
        return card;
    }

    private void ShowView(bool simple)
    {
        _showSimple = simple;
        _viewHost.Controls.Clear();
        var v = simple ? _simplePanel : _advPanel;
        v.Dock = DockStyle.Fill;
        _viewHost.Controls.Add(v);
        _advToggleBtn.Text = simple ? "Advanced ▸" : "◀ Simple";
    }

    private void SelectTabByName(string name)
    {
        foreach (TabPage tp in _tabs.TabPages)
            if (tp.Text.Equals(name, StringComparison.OrdinalIgnoreCase)) { _tabs.SelectedTab = tp; return; }
    }

    private void SyncFromAdvanced()
    {
        if (_syncing) return;
        _syncing = true;
        _simpleModeBox.SelectedIndex = _modeBox.SelectedIndex;
        _simplePayloadBox.Text = _payloadBox.Text;
        _syncing = false;
    }

    private void SyncFromSimple()
    {
        if (_syncing) return;
        _syncing = true;
        _modeBox.SelectedIndex = _simpleModeBox.SelectedIndex;
        _payloadBox.Text = _simplePayloadBox.Text;
        _syncing = false;
        UpdateModeUi();
    }

    private void SetSimpleStatus(string text, bool ok = true)
    {
        _simpleStatus.ForeColor = ok ? CDim : Color.FromArgb(240, 110, 115);
        _simpleStatus.Text = text;
    }

    private void UpdateInjectCards()
    {
        SetCard(_cardDllTitle, _cardDllBody, "DLL");
        SetCard(_cardMemTitle, _cardMemBody, "Memory");
        SetCard(_cardMonoTitle, _cardMonoBody, "Mono", accent: true);
    }

    private void SetCard(Label title, Label body, string mode, bool accent = false)
    {
        title.Text = accent ? "MONO ★" : mode.ToUpperInvariant();
        if (_lastByMode.TryGetValue(mode, out var it))
        {
            bool ok = it.Status == "Success";
            string file = Path.GetFileName(it.Payload);
            string when = it.Time.ToString("HH:mm:ss");
            string target = _proc is { } p ? $"{p.Name} (PID {p.Pid})" : it.Target;
            if (mode == "Mono" && it.Target.Contains('→'))
                target = it.Target[(it.Target.IndexOf('→') + 1)..].Trim();
            body.ForeColor = ok ? COk : Color.FromArgb(235, 95, 100);
            body.Text = (ok ? "✓ " : "✗ ") + file + "\n" + target + "\n" + when +
                        (ok ? "" : "  — see Injected tab");
        }
        else
        {
            body.ForeColor = CDim;
            body.Text = accent
                ? "— no mono injection yet —\npick a managed dll below, hit Inject ▶"
                : "— nothing injected yet —";
        }
    }

    /// <summary>Refreshes the recover dropdown — injected dlls appear here once mapped.</summary>
    private void RebuildRecoverList()
    {
        string? keep = _recoverBox.SelectedItem as string;
        _recoverBox.BeginUpdate();
        _recoverBox.Items.Clear();
        foreach (var m in _modules)
            if (!string.IsNullOrEmpty(m.Name))
                _recoverBox.Items.Add(m.Name);
        _recoverBox.EndUpdate();

        if (keep is not null && _recoverBox.Items.Contains(keep))
            _recoverBox.SelectedItem = keep;                       // keep the current pick
        else if (_lastByMode.TryGetValue("Mono", out var last) &&    // else prefer the dll we just injected
                 _recoverBox.Items.Contains(Path.GetFileName(last.Payload)))
            _recoverBox.SelectedItem = Path.GetFileName(last.Payload);
        else if (_recoverBox.Items.Count > 0)
            _recoverBox.SelectedIndex = 0;
        UpdateButtons();
    }

    // =========================================================================
    // recover a dll (dump a module straight out of the target's memory)
    // =========================================================================
    private async Task RecoverModuleAsync()
    {
        if (_proc is null || _recovering) return;
        if (_recoverBox.SelectedItem is not string sel)
        {
            MessageBox.Show(this, "Pick a module to recover from the dropdown.", "Dll Dumper",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var mod = _modules.FirstOrDefault(m => m.Name == sel);
        if (mod is null)
        {
            SetSimpleStatus($"module \"{sel}\" is no longer loaded in the target", false);
            return;
        }

        using var sfd = new SaveFileDialog
        {
            Title = $"Recover {sel} from {_proc.Name}",
            Filter = "Dynamic-link library (*.dll)|*.dll|Executable (*.exe)|*.exe|All files (*.*)|*.*",
            FileName = Path.GetFileName(mod.Path.Length > 0 ? mod.Path : sel),
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        _recovering = true;
        UpdateButtons();
        string outPath = sfd.FileName;
        SetSimpleStatus($"recovering {sel} ({MemoryRegion.FormatSize(mod.Size)}) from {_proc.Name}'s memory…");
        SetStatus($"recovering {sel} → {outPath} …");

        string summary;
        try
        {
            var proc = _proc;
            var m = mod;
            summary = await Task.Run(() => ModuleDumper.Dump(proc.Handle, m, outPath));
        }
        catch (Exception ex)
        {
            _recovering = false;
            UpdateButtons();
            _rec.RecordError("recover", ex.Message);
            SetSimpleStatus($"✗ could not recover {sel}: {ex.Message}", false);
            SetStatus("recover failed: " + ex.Message, true);
            return;
        }

        _recovering = false;
        UpdateButtons();
        _rec.Add("Recover", sel, $"{summary} → {outPath}");
        long bytes = new FileInfo(outPath).Length;
        SetSimpleStatus($"✓ recovered {sel} → {Path.GetFileName(outPath)} ({MemoryRegion.FormatSize(bytes)})");
        SetStatus($"recovered {sel} → {outPath} · {summary}");
    }

    /// <summary>Finds a static entry point inside a managed payload so mono mode "just works".</summary>
    private static bool TryAutoEntry(string payloadPath, out string ns, out string cls, out string method)
    {
        ns = cls = method = "";
        try
        {
            var scan = MonoInspector.ScanAssemblies(new List<string> { payloadPath });
            var asm = scan.Assemblies.FirstOrDefault();
            if (asm is null) return false;

            var types = asm.Types.Where(t => t.Methods.Count > 0).ToList();
            if (types.Count == 0) return false;

            static bool Has(string s, params string[] keys) =>
                keys.Any(k => s.Contains(k, StringComparison.OrdinalIgnoreCase));

            var type = types.FirstOrDefault(t => Has(t.FullName, "Loader", "Plugin", "Bootstrap", "Entry", "Main"))
                    ?? types[0];
            var meth = type.Methods.FirstOrDefault(x => x is "Load" or "Init" or "Initialize" or "Main" or "Start" or "Awake" or "Run")
                    ?? type.Methods.FirstOrDefault(x => Has(x, "Load", "Init", "Start", "Run", "Main"))
                    ?? type.Methods[0];

            string full = type.FullName;
            int dot = full.LastIndexOf('.');
            if (dot > 0) { ns = full[..dot]; cls = full[(dot + 1)..]; }
            else cls = full;
            method = meth;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void BuildTabs()
    {
        _tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            DrawMode = TabDrawMode.OwnerDrawFixed,
            SizeMode = TabSizeMode.Fixed,
            ItemSize = new Size(138, 30),
            BackColor = CPanel,
            ForeColor = CText,
            Font = FUi,
            Padding = new Point(8, 4),
            Margin = Padding.Empty,
        };
        _tabs.DrawItem += (_, e) =>
        {
            if (e.Index < 0 || e.Index >= _tabs.TabPages.Count) return;
            bool sel = e.Index == _tabs.SelectedIndex;
            using (var bg = new SolidBrush(sel ? Color.FromArgb(46, 46, 54) : CPanel))
                e.Graphics.FillRectangle(bg, e.Bounds);
            if (sel)
                using (var accent = new SolidBrush(CRed))
                    e.Graphics.FillRectangle(accent, e.Bounds.Left, e.Bounds.Bottom - 2, e.Bounds.Width, 2);
            TextRenderer.DrawText(e.Graphics, _tabs.TabPages[e.Index].Text, _tabs.Font, e.Bounds,
                sel ? Color.White : CDim,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        };

        // ---- Mono ----
        _searchBox = MakeTextBox();
        _searchBtn = MakeButton("Search");
        var searchPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        searchPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        searchPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        searchPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        searchPanel.Controls.Add(_searchBox, 0, 0);
        searchPanel.Controls.Add(_searchBtn, 1, 0);

        _monoInfo = InfoLabel();
        _monoList = MakeListView(("Assembly / module", 175), ("Kind", 78), ("Name", 360), ("Detail", 300));

        var monoBody = Stack(
            searchPanel, new RowStyle(SizeType.Absolute, 32),
            _monoInfo, new RowStyle(SizeType.Absolute, 26),
            _monoList, new RowStyle(SizeType.Percent, 100));

        // ---- Memory ----
        _memInfo = InfoLabel();
        _memList = MakeListView(("Base", 130), ("Size", 84), ("State", 68), ("Protect", 96), ("Type", 74), ("Content / owner", 340));
        var memBody = Stack(
            _memInfo, new RowStyle(SizeType.Absolute, 26),
            _memList, new RowStyle(SizeType.Percent, 100));

        // ---- Files ----
        _filesInfo = InfoLabel();
        _filesList = MakeListView(("Path", 430), ("Kind", 84), ("Base", 130), ("Size", 84));
        var filesBody = Stack(
            _filesInfo, new RowStyle(SizeType.Absolute, 26),
            _filesList, new RowStyle(SizeType.Percent, 100));

        // ---- Recorded ----
        _recInfo = InfoLabel();
        _saveBtn = MakeButton("Save report");
        var recToolbar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        recToolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        recToolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 118));
        recToolbar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        recToolbar.Controls.Add(_recInfo, 0, 0);
        recToolbar.Controls.Add(_saveBtn, 1, 0);
        _recList = MakeListView(("Time", 96), ("Kind", 92), ("Item", 380), ("Detail", 380));
        var recBody = Stack(
            recToolbar, new RowStyle(SizeType.Absolute, 32),
            _recList, new RowStyle(SizeType.Percent, 100));

        // ---- Injected ----
        _injInfo = InfoLabel();
        _injList = MakeListView(("Time", 88), ("Mode", 76), ("Payload", 250), ("Target / entry", 340), ("Status", 90));
        _injDetail = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = CDark,
            ForeColor = CText,
            BorderStyle = BorderStyle.FixedSingle,
            Font = FData,
            WordWrap = false,
            Margin = Padding.Empty,
        };
        var injBody = Stack(
            _injInfo, new RowStyle(SizeType.Absolute, 26),
            _injList, new RowStyle(SizeType.Percent, 48),
            _injDetail, new RowStyle(SizeType.Percent, 52));

        _tabs.TabPages.Add(MakeTab("Mono", monoBody));
        _tabs.TabPages.Add(MakeTab("Memory", memBody));
        _tabs.TabPages.Add(MakeTab("Files", filesBody));
        _tabs.TabPages.Add(MakeTab("Recorded", recBody));
        _tabs.TabPages.Add(MakeTab("Injected", injBody));
    }

    // =========================================================================
    // layout helpers
    // =========================================================================
    private static TableLayoutPanel RowPanel(params ColumnStyle[] styles)
    {
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = styles.Length,
            RowCount = 1,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
        };
        foreach (var s in styles) t.ColumnStyles.Add(s);
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        return t;
    }

    /// <summary>Vertical stack of alternating control / row-style pairs.</summary>
    private static TableLayoutPanel Stack(params object[] parts)
    {
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = parts.Length / 2,
            Margin = Padding.Empty,
            Padding = Padding.Empty,
        };
        for (int i = 0; i < parts.Length; i += 2)
        {
            t.RowStyles.Add((RowStyle)parts[i + 1]);
            t.Controls.Add((Control)parts[i], 0, i / 2);
        }
        return t;
    }

    private static TabPage MakeTab(string title, Control content)
    {
        var page = new TabPage
        {
            Text = title,
            BackColor = CPanel,
            ForeColor = CText,
            Padding = new Padding(10, 6, 10, 10),
        };
        page.Controls.Add(content);
        return page;
    }

    private static Label InfoLabel() => new()
    {
        Dock = DockStyle.Fill,
        ForeColor = CDim,
        Font = FSub,
        TextAlign = ContentAlignment.MiddleLeft,
        Padding = new Padding(4, 0, 0, 0),
        AutoEllipsis = true,
        Text = "",
    };

    private static TextBox MakeTextBox() => new()
    {
        Dock = DockStyle.Fill,
        BackColor = CField,
        ForeColor = CText,
        BorderStyle = BorderStyle.FixedSingle,
        Font = FUi,
        Margin = new Padding(0, 5, 0, 5),
    };

    private static Button MakeButton(string text, bool accent = false) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        FlatStyle = FlatStyle.Flat,
        BackColor = accent ? CRedDark : CField,
        ForeColor = accent ? Color.White : CText,
        Font = FUi,
        Cursor = Cursors.Hand,
        Margin = new Padding(0, 4, 0, 4),
        UseVisualStyleBackColor = false,
        FlatAppearance =
        {
            BorderColor = accent ? CRed : CLine,
            BorderSize = 1,
            MouseOverBackColor = accent ? Color.FromArgb(140, 36, 43) : Color.FromArgb(50, 50, 58),
            MouseDownBackColor = accent ? Color.FromArgb(90, 24, 30) : Color.FromArgb(58, 58, 68),
        },
    };

    private static Button AccentButton(string text) => MakeButton(text, accent: true);

    private static ListView MakeListView(params (string Text, int Width)[] cols)
    {
        var lv = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HideSelection = false,
            BackColor = CDark,
            ForeColor = CText,
            BorderStyle = BorderStyle.FixedSingle,
            Font = FData,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
        };
        foreach (var (text, width) in cols)
            lv.Columns.Add(new ColumnHeader { Text = text, Width = width });

        lv.Resize += (_, _) =>
        {
            if (lv.Columns.Count == 0) return;
            int w = lv.ClientSize.Width - 6;
            for (int i = 0; i < lv.Columns.Count - 1; i++) w -= lv.Columns[i].Width;
            var last = lv.Columns[lv.Columns.Count - 1];
            last.Width = Math.Max(70, w);
        };
        return lv;
    }

    // =========================================================================
    // process list
    // =========================================================================
    private async Task RefreshProcessesAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        UpdateButtons();
        try
        {
            int keep = _proc?.Pid ?? -1;
            if (keep < 0 && _procList.SelectedItems.Count > 0 && _procList.SelectedItems[0].Tag is int t)
                keep = t;

            var list = await Task.Run(() =>
            {
                var outp = new List<(string Name, int Pid, string Title, long Ws)>();
                foreach (var p in Process.GetProcesses())
                {
                    using (p)
                    {
                        string title = "";
                        long ws = 0;
                        try { title = p.MainWindowTitle ?? ""; } catch { /* system process */ }
                        try { ws = p.WorkingSet64; } catch { /* exited */ }
                        outp.Add((p.ProcessName, p.Id, title, ws));
                    }
                }
                outp.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
                return outp;
            });

            _processes = list;
            ApplyProcessFilter();

            if (keep >= 0)
            {
                _suppressProcSelect = true;
                foreach (ListViewItem it in _procList.Items)
                    if (it.Tag is int pid && pid == keep)
                    {
                        it.Selected = true;
                        it.EnsureVisible();
                        break;
                    }
                _suppressProcSelect = false;
            }
            SetStatus($"{list.Count} processes found — pick one (F5 refreshes).");
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
        finally
        {
            _refreshing = false;
            UpdateButtons();
        }
    }

    /// <summary>DllDumper.exe [process-name | pid] [tab-name] — preselects a process and tab on startup.</summary>
    private Task SelectFromArgsAsync()
    {
        if (_startupArgs.Length == 0) return Task.CompletedTask;
        string wanted = _startupArgs[0];
        int pid = -1;

        if (int.TryParse(wanted, out int asPid))
            pid = asPid;
        else
            foreach (var (name, p, _, _) in _processes)
                if (name.Equals(wanted, StringComparison.OrdinalIgnoreCase))
                {
                    pid = p;
                    break;
                }

        if (pid < 0)
        {
            SetStatus($"startup target \"{wanted}\" was not found in the process list");
            return Task.CompletedTask;
        }

        foreach (ListViewItem it in _procList.Items)
            if (it.Tag is int p && p == pid)
            {
                it.Selected = true;     // fires OnProcessSelected → SelectProcess
                it.EnsureVisible();
                return Task.CompletedTask;
            }

        SetStatus($"startup target \"{wanted}\" (PID {pid}) is not running");
        return Task.CompletedTask;
    }

    private void SelectTabFromArgs()
    {
        if (_startupArgs.Length < 2) return;
        string want = _startupArgs[1];
        foreach (TabPage tp in _tabs.TabPages)
            if (tp.Text.Equals(want, StringComparison.OrdinalIgnoreCase))
            {
                _tabs.SelectedTab = tp;
                ShowView(simple: false);   // a tab was requested → open the advanced view
                return;
            }
    }

    private void ApplyProcessFilter()
    {
        string q = _filterBox.Text.Trim();
        _suppressProcSelect = true;
        _procList.BeginUpdate();
        _procList.Items.Clear();
        foreach (var (name, pid, title, ws) in _processes)
        {
            if (q.Length > 0 &&
                !name.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !pid.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !title.Contains(q, StringComparison.OrdinalIgnoreCase))
                continue;

            var item = new ListViewItem(new[]
            {
                name,
                pid.ToString(),
                title,
                $"{ws / 1048576.0:0.#} MB",
            });
            item.Tag = pid;
            _procList.Items.Add(item);
        }
        _procList.EndUpdate();
        _suppressProcSelect = false;
    }

    private void OnProcessSelected()
    {
        if (_suppressProcSelect || _procList.SelectedItems.Count == 0) return;
        if (_procList.SelectedItems[0].Tag is not int pid) return;
        SelectProcess(pid);
    }

    private void SelectProcess(int pid)
    {
        try
        {
            if (_rec.IsRecording) StopRecordingInternal("selection changed");
            ResetState();

            var p = new ProcessInspector(pid);
            _proc = p;

            _targetLabel.Text =
                $"{p.Name}  ·  PID {p.Pid}  ·  {p.Architecture}\n" +
                $"{p.ExePath ?? "(path unavailable)"}";

            SetSimpleStatus($"ready — {p.Name} selected · press RECORD");
            SetStatus($"Selected {p.Name} (PID {pid}) — press ● Record to capture mono, memory and files.");
            UpdateButtons();
            _ = RunCaptureAsync();
        }
        catch (Exception ex)
        {
            ResetState();
            SetStatus(ex.Message, true);
            MessageBox.Show(this, ex.Message, "Dll Dumper — cannot inspect process",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            UpdateButtons();
        }
    }

    private void ResetState()
    {
        _version++;
        _rec.Reset();
        _proc?.Dispose();
        _proc = null;
        _runtime = null;
        _assemblies.Clear();
        _scannedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _modules.Clear();
        _regions.Clear();
        _haveBaseline = false;
        _lastFiles = -1;
        _lastRegions = -1;
        _lastRecoverCount = -1;
        _injTotal = 0;
        _injOk = 0;
        _lastByMode.Clear();
        UpdateInjectCards();

        _monoList.Items.Clear();
        _memList.Items.Clear();
        _filesList.Items.Clear();
        _recList.Items.Clear();
        _injList.Items.Clear();
        _injDetail.Text = "";
        _monoInfo.Text = "";
        _memInfo.Text = "";
        _filesInfo.Text = "";
        _injInfo.Text = "";
        _searchBox.Text = "";
        _recoverBox.Items.Clear();
        _targetLabel.Text = "no process selected";
        SetSimpleStatus("no process selected — pick one on the left");
        UpdateRecordUi();
    }

    // =========================================================================
    // capture
    // =========================================================================
    private sealed class Snapshot
    {
        public List<ModuleInfo> Modules = new();
        public List<MemoryRegion> Regions = new();
        public MonoRuntime? Runtime;
        public MonoScanResult? NewMono;
        public int CommittedCount;
        public long CommittedBytes;
    }

    private static Snapshot TakeSnapshot(ProcessInspector proc, HashSet<string> scanned, MonoRuntime? known)
    {
        var s = new Snapshot();
        s.Modules = proc.GetModules();
        s.Regions = proc.WalkMemory(s.Modules);
        s.Runtime = known ?? MonoInspector.Detect(s.Modules);

        var newPaths = new List<string>();
        foreach (var m in s.Modules)
            if (!string.IsNullOrEmpty(m.Path) && scanned.Add(m.Path))
                newPaths.Add(m.Path);
        if (newPaths.Count > 0)
            s.NewMono = MonoInspector.ScanAssemblies(newPaths);

        foreach (var r in s.Regions)
            if (r.State == Native.MEM_COMMIT)
            {
                s.CommittedCount++;
                s.CommittedBytes += r.Size;
            }
        return s;
    }

    private async Task RunCaptureAsync()
    {
        if (_capturing || _proc is null) return;
        _capturing = true;
        int version = _version;
        var proc = _proc;
        var scanned = _scannedPaths;
        var known = _runtime;
        try
        {
            var snap = await Task.Run(() => TakeSnapshot(proc, scanned, known));
            if (version != _version) return;    // another process was selected meanwhile
            ApplySnapshot(snap);
        }
        catch (Exception ex)
        {
            if (version == _version)
            {
                _rec.RecordError("capture", ex.Message);
                SetStatus(ex.Message, true);
            }
        }
        finally
        {
            _capturing = false;
        }
    }

    private void ApplySnapshot(Snapshot s)
    {
        _modules = s.Modules;
        _regions = s.Regions;

        bool monoChanged = false;
        if (s.Runtime is not null && _runtime is null)
        {
            _runtime = s.Runtime;
            monoChanged = true;
        }
        if (s.NewMono is { Assemblies.Count: > 0 } nm)
        {
            _assemblies.AddRange(nm.Assemblies);
            monoChanged = true;
        }

        RebuildFiles();
        RebuildMemory();
        if (monoChanged) ApplyMonoSearch();
        if (_modules.Count != _lastRecoverCount)
        {
            _lastRecoverCount = _modules.Count;
            RebuildRecoverList();   // newly injected dlls show up in the recover list
        }

        if (_rec.IsRecording)
        {
            _recList.BeginUpdate();
            try
            {
                if (_runtime is { } rt)
                {
                    _rec.AddOnce("mono:detected", "Mono", $"{rt.KindName} runtime detected",
                        $"{rt.ModuleName} @ 0x{rt.ModuleBase.ToInt64():X} · {rt.Exports.Count} exports" +
                        (rt.ExportError.Length > 0 ? $" · {rt.ExportError}" : ""));
                    foreach (var e in rt.Exports)
                        _rec.RecordMonoExport(rt, e);
                }
                foreach (var a in _assemblies) _rec.RecordAssembly(a);
                foreach (var m in s.Modules) _rec.RecordModule(m);
                foreach (var r in s.Regions) _rec.RecordMemory(r, 64 * 1024);

                string summary =
                    $"{s.Modules.Count} files · {s.Regions.Count} regions · " +
                    $"{MemoryRegion.FormatSize(s.CommittedBytes)} committed · {_assemblies.Count} assemblies";
                if (!_haveBaseline)
                {
                    _rec.Add("Mono", "baseline captured", summary);
                    _haveBaseline = true;
                }
                else if (s.Modules.Count != _lastFiles || s.Regions.Count != _lastRegions)
                {
                    _rec.Add("Memory", "map updated", summary);
                }
                _lastFiles = s.Modules.Count;
                _lastRegions = s.Regions.Count;
            }
            finally
            {
                _recList.EndUpdate();
            }
        }

        UpdateInfos(s);
        SetStatus($"captured {s.Modules.Count} files · {s.Regions.Count} memory regions · " +
                  $"{_assemblies.Count} managed assemblies · mono: {_runtime?.KindName ?? "not present"}");
    }

    private void RebuildFiles()
    {
        _filesList.BeginUpdate();
        _filesList.Items.Clear();
        foreach (var m in _modules)
        {
            string kind = _proc?.ExePath is { Length: > 0 } exe &&
                          string.Equals(m.Path, exe, StringComparison.OrdinalIgnoreCase)
                ? "Main exe"
                : m.IsManaged ? "Managed" : "Native";
            _filesList.Items.Add(new ListViewItem(new[]
            {
                string.IsNullOrEmpty(m.Path) ? m.Name : m.Path,
                kind,
                m.BaseHex,
                MemoryRegion.FormatSize(m.Size),
            }));
        }
        _filesList.EndUpdate();
    }

    private void RebuildMemory()
    {
        _memList.BeginUpdate();
        _memList.Items.Clear();
        foreach (var r in _regions)
        {
            var item = new ListViewItem(new[]
            {
                r.BaseHex,
                r.SizeText,
                r.StateText,
                r.ProtectText,
                r.TypeText,
                r.Owner,
            });
            if (r.State == Native.MEM_COMMIT && (r.Protect & 0xFF) == 0x10)
                item.ForeColor = Color.FromArgb(150, 150, 160);
            _memList.Items.Add(item);
        }
        _memList.EndUpdate();
    }

    private void UpdateInfos(Snapshot s)
    {
        _filesInfo.Text =
            $"{s.Modules.Count} files mapped · {s.Modules.Count(m => m.IsManaged)} managed assemblies · " +
            $"main: {_proc?.ExePath ?? "?"}";

        _memInfo.Text =
            $"{s.Regions.Count} regions · {s.CommittedCount} committed ({MemoryRegion.FormatSize(s.CommittedBytes)}) · " +
            $"{_regions.Count(r => r.Type == Native.MEM_IMAGE)} image · " +
            $"{_regions.Count(r => r.Type == Native.MEM_PRIVATE)} private · " +
            $"{_regions.Count(r => r.Type == Native.MEM_MAPPED)} mapped";

        UpdateMonoInfo();
        UpdateRecordUi();
        UpdateInjectInfo();
    }

    private void UpdateMonoInfo(string? queryNote = null)
    {
        var rt = _runtime;
        string runtime = rt is null
            ? "no managed runtime detected (mono*.dll / GameAssembly.dll / coreclr.dll not loaded)"
            : $"{rt.KindName}: {rt.ModuleName} @ 0x{rt.ModuleBase.ToInt64():X} · {rt.Exports.Count:N0} exports" +
              (rt.ExportError.Length > 0 ? $" · {rt.ExportError}" : "");

        long types = 0, methods = 0;
        foreach (var a in _assemblies) { types += a.TypeCount; methods += a.MethodCount; }

        string baseInfo = $"{runtime} · {_assemblies.Count} assemblies · {types:N0} types · {methods:N0} methods";
        _monoInfo.Text = queryNote is null ? baseInfo : $"{baseInfo}  —  {queryNote}";
    }

    // =========================================================================
    // mono tab (default view + search)
    // =========================================================================
    private async void ApplyMonoSearch()
    {
        int v = ++_searchVersion;
        string q = _searchBox.Text.Trim();
        var assemblies = _assemblies.ToArray();
        var runtime = _runtime;

        var (rows, matches, capped) = await Task.Run(() => BuildMonoRows(q, assemblies, runtime));
        if (v != _searchVersion || IsDisposed) return;

        _monoList.BeginUpdate();
        _monoList.Items.Clear();
        int shown = 0;
        foreach (var r in rows)
        {
            if (shown++ >= MonoDisplayCap) break;
            _monoList.Items.Add(new ListViewItem(new[] { r.Src, r.Kind, r.Name, r.Detail }));
        }
        _monoList.EndUpdate();

        string note = q.Length == 0
            ? "listing assemblies + runtime exports — type a query to search types, methods and exports"
            : $"{matches:N0}{(capped ? "+" : "")} matches for \"{q}\" · showing {Math.Min(shown, MonoDisplayCap):N0}";
        UpdateMonoInfo(note);
    }

    private static (List<MonoRow> Rows, int Matches, bool Capped) BuildMonoRows(
        string q, AssemblyScan[] assemblies, MonoRuntime? rt)
    {
        var rows = new List<MonoRow>(256);
        int matches = 0;
        bool capped = false;
        bool empty = q.Length == 0;

        if (rt is not null)
            foreach (var e in rt.Exports)
            {
                if (!empty && !e.Name.Contains(q, StringComparison.OrdinalIgnoreCase)) continue;
                matches++;
                if (rows.Count >= MonoBuildCap) { capped = true; break; }
                rows.Add(new(rt.ModuleName, "Export", e.Name,
                    e.AddressHex + (e.Forwarded ? " (forwarded)" : "")));
            }

        if (!capped)
            foreach (var a in assemblies)
            {
                if (empty || a.Name.Contains(q, StringComparison.OrdinalIgnoreCase))
                {
                    matches++;
                    if (rows.Count >= MonoBuildCap) { capped = true; break; }
                    rows.Add(new(a.Name, "Assembly", a.Name, $"{a.TypeCount} types · {a.MethodCount} methods"));
                }
                if (empty) continue;

                foreach (var t in a.Types)
                {
                    if (t.FullName.Contains(q, StringComparison.OrdinalIgnoreCase))
                    {
                        matches++;
                        if (rows.Count >= MonoBuildCap) { capped = true; break; }
                        rows.Add(new(a.Name, "Type", t.FullName, $"{t.Methods.Count} methods"));
                    }
                    foreach (var m in t.Methods)
                    {
                        if (!m.Contains(q, StringComparison.OrdinalIgnoreCase)) continue;
                        matches++;
                        if (rows.Count >= MonoBuildCap) { capped = true; break; }
                        rows.Add(new(a.Name, "Method", m, t.FullName));
                    }
                    if (capped) break;
                }
                if (capped) break;
            }

        return (rows, matches, capped);
    }

    // =========================================================================
    // record / stop
    // =========================================================================
    private async Task RecordAsync()
    {
        if (_proc is null)
        {
            MessageBox.Show(this, "Select a process from the list first.",
                "Dll Dumper", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (_rec.IsRecording) return;

        try
        {
            _rec.StartSession();
            UpdateRecordUi();
            UpdateButtons();
            SetSimpleStatus($"capturing {_proc.Name} — mono, memory and files…");
            SetStatus($"● recording {_proc.Name} — capturing mono, memory and files…");
            await RunCaptureAsync();
            _tickTimer.Start();
            SetStatus($"● Recording {_proc.Name} (PID {_proc.Pid}) — new files / regions / assemblies are " +
                      "logged live, and every injection is logged too.");
        }
        catch (Exception ex)
        {
            _rec.StopSession("capture failed");
            _tickTimer.Stop();
            SetStatus(ex.Message, true);
        }
        finally
        {
            UpdateButtons();
            UpdateRecordUi();
        }
    }

    private async Task StopAsync()
    {
        if (!_rec.IsRecording) return;
        SetStatus("finishing final capture…");
        await RunCaptureAsync();

        long types = 0, methods = 0;
        foreach (var a in _assemblies) { types += a.TypeCount; methods += a.MethodCount; }
        string summary =
            $"{_modules.Count} files · {_regions.Count} regions · {_assemblies.Count} assemblies " +
            $"({types:N0} types / {methods:N0} methods) · {_rec.Injections.Count} injections · " +
            $"{_rec.Items.Count:N0} log entries";

        _tickTimer.Stop();
        string msg = _rec.StopSession(summary);
        UpdateButtons();
        UpdateRecordUi();
        SetSimpleStatus($"{msg} · {_rec.Items.Count:N0} items — open Advanced ▸ Recorded to inspect");
        SetStatus($"{msg}. {_rec.Items.Count:N0} recorded items — see the Recorded tab (Save report exports it).");
    }

    private void StopRecordingInternal(string reason)
    {
        if (!_rec.IsRecording) return;
        _tickTimer.Stop();
        _rec.StopSession($"{reason} · {_rec.Items.Count:N0} entries · {_rec.Injections.Count} injections");
        UpdateButtons();
        UpdateRecordUi();
    }

    private void OnRecordAdded(RecordItem item)
    {
        var row = new ListViewItem(new[]
        {
            item.Time.ToString("HH:mm:ss.fff"),
            item.Kind,
            item.Item,
            item.Detail,
        });
        if (item.Kind == "Error" || item.Detail.StartsWith("FAILED", StringComparison.Ordinal))
            row.ForeColor = Color.FromArgb(235, 95, 100);
        else if (item.Kind is "Session" or "Inject")
            row.ForeColor = CRed;
        else if (item.Kind == "Mono")
            row.ForeColor = Color.FromArgb(150, 195, 255);

        _recList.Items.Add(row);
        if (_recList.Items.Count > RecordViewCap)
            for (int i = 0; i < 500 && _recList.Items.Count > 0; i++)
                _recList.Items.RemoveAt(0);
    }

    private void UpdateRecordUi()
    {
        bool on = _rec.IsRecording;
        _recLabel.Text = on ? $"● REC {_rec.Elapsed:mm\\:ss}" : "○ IDLE";
        if (!on) _recLabel.ForeColor = CDim;

        string drop = _rec.DroppedCount > 0 ? $" · {_rec.DroppedCount:N0} dropped (log full)" : "";
        _recInfo.Text =
            (on ? $"● recording — {_rec.Elapsed:hh\\:mm\\:ss} · " : "○ not recording · ") +
            $"{_rec.Items.Count:N0} entries · {_rec.Injections.Count} injections" + drop;
    }

    private void UpdateInjectInfo()
    {
        _injInfo.Text = $"{_injTotal} injections · {_injOk} succeeded · select a row to see its full step log";
    }

    private void UpdateButtons()
    {
        bool busy = _injecting || _recovering;
        _bigRecordBtn.Enabled = _proc is not null && !busy;
        if (!_rec.IsRecording) _bigRecordBtn.Text = "●  R E C O R D";
        _simpleInjectBtn.Enabled = _proc is not null && !busy;
        _injectBtn.Enabled = _proc is not null && !busy;
        _recoverBtn.Enabled = _proc is not null && !busy && _recoverBox.Items.Count > 0;
        _recoverBox.Enabled = _recoverBtn.Enabled;
        _refreshBtn.Enabled = !_refreshing;
    }

    // =========================================================================
    // injection
    // =========================================================================
    private void BrowsePayload()
    {
        string mode = _modeBox.SelectedItem?.ToString() ?? "DLL";
        using var ofd = new OpenFileDialog();
        ofd.Title = "Choose payload";
        ofd.Filter = mode switch
        {
            "Mono" => "Managed assembly (*.dll)|*.dll|All files (*.*)|*.*",
            "Memory" => "Payload (*.bin;*.raw;*.exe;*.dll)|*.bin;*.raw;*.exe;*.dll|All files (*.*)|*.*",
            _ => "Library / assembly (*.dll;*.exe)|*.dll;*.exe|All files (*.*)|*.*",
        };
        if (ofd.ShowDialog(this) == DialogResult.OK)
            _payloadBox.Text = ofd.FileName;
    }

    private void UpdateModeUi()
    {
        string mode = _modeBox.SelectedItem?.ToString() ?? "DLL";
        bool mono = mode == "Mono";

        _hintLabel.Text = mode switch
        {
            "DLL" => "DLL mode — LoadLibraryW inside the target (native plugins, bootstraps, .dll menus).",
            "Memory" => "Memory mode — payload bytes are written into a fresh region" +
                        (_execBox.Checked ? " and executed as a remote thread." : " (memory only, not executed)."),
            _ => "Mono mode — opens the assembly with the target's own runtime and invokes a static method.",
        };

        _labelEntry.Enabled = mono;
        _nsBox.Enabled = mono;
        _clsBox.Enabled = mono;
        _methodBox.Enabled = mono;
        _paramBox.Enabled = mono;
        _nsBox.BackColor = mono ? CField : CDark;
        _clsBox.BackColor = mono ? CField : CDark;
        _methodBox.BackColor = mono ? CField : CDark;
        _paramBox.BackColor = mono ? CField : CDark;
        _execBox.Visible = mode == "Memory";

        if (mono && _runtime is { } rt && rt.Kind != RuntimeKind.Mono)
            SetStatus($"warning: selected target is {rt.KindName}, not Mono — mono mode will likely fail", true);
    }

    private async Task InjectAsync()
    {
        if (_proc is null)
        {
            MessageBox.Show(this, "Select a process first.", "Dll Dumper",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (_injecting) return;

        string mode = _modeBox.SelectedItem?.ToString() ?? "DLL";
        string payload = _payloadBox.Text.Trim();
        if (payload.Length == 0 || !File.Exists(payload))
        {
            MessageBox.Show(this, "Pick a payload file first (Browse… or drag & drop onto this window).",
                "Dll Dumper", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        int? pc = null;
        string entry = "";
        if (mode == "Mono")
        {
            string ns = _nsBox.Text.Trim(), cls = _clsBox.Text.Trim(),
                   m = _methodBox.Text.Trim(), ps = _paramBox.Text.Trim();

            if (cls.Length == 0 || m.Length == 0)
            {
                // simple view: no entry typed — pick one straight out of the payload dll
                if (!TryAutoEntry(payload, out ns, out cls, out m))
                {
                    MessageBox.Show(this,
                        "Mono mode needs a class and a static method name.\n" +
                        "(e.g. class: Loader, method: Load) — or use a payload that has managed metadata.",
                        "Dll Dumper", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                _nsBox.Text = ns; _clsBox.Text = cls; _methodBox.Text = m;   // mirror into the advanced view
                SetStatus($"mono entry auto-picked from the payload: {(ns.Length > 0 ? ns + "." : "")}{cls}.{m}()");
            }
            if (ps.Length > 0)
            {
                if (!int.TryParse(ps, out int v) || v < 0 || v > 32)
                {
                    MessageBox.Show(this, "Parameter count must be a number between 0 and 32 (or empty).",
                        "Dll Dumper", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                pc = v;
            }
            entry = $"{(ns.Length > 0 ? ns + "." : "")}{cls}.{m}()";
        }

        var item = new InjectItem
        {
            Mode = mode,
            Payload = payload,
            Target = $"{_proc.Name} (PID {_proc.Pid})" + (entry.Length > 0 ? " → " + entry : ""),
        };
        var row = new ListViewItem(new[]
        {
            DateTime.Now.ToString("HH:mm:ss"),
            mode,
            Path.GetFileName(payload),
            item.Target,
            "Running",
        });
        row.Tag = item;
        _injList.Items.Insert(0, row);
        _injTotal++;
        UpdateInjectInfo();

        _injecting = true;
        UpdateButtons();
        SetStatus($"injecting ({mode}) {Path.GetFileName(payload)} → {_proc.Name} …");

        int pid = _proc.Pid;
        int version = _version;
        Action<string> step = msg =>
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(() => OnInjectStep(item, msg)); } catch { /* closing */ }
        };

        InjectionResult res;
        try
        {
            res = await Task.Run(() => mode switch
            {
                "Memory" => Injector.InjectMemory(pid, payload, _execBox.Checked, step),
                "Mono" => Injector.InjectMono(pid, payload, _nsBox.Text.Trim(), _clsBox.Text.Trim(),
                              _methodBox.Text.Trim(), pc, step),
                _ => Injector.InjectDll(pid, payload, step),
            });
        }
        catch (Exception ex)
        {
            res = new InjectionResult { Summary = ex.Message };
            res.Step("FAILED · " + ex.Message);
            step("FAILED · " + ex.Message);
        }

        if (item.Steps.Count == 0)
            foreach (var s2 in res.Steps)
                item.Steps.Add(s2);

        item.Status = res.Success ? "Success" : "Failed";
        row.SubItems[4].Text = item.Status;
        row.ForeColor = res.Success ? COk : Color.FromArgb(235, 95, 100);
        if (res.Success) _injOk++;

        _rec.RecordInjection(item);
        _lastByMode[mode] = item;
        UpdateInjectCards();
        _injDetail.Text = string.Join(Environment.NewLine, item.Steps);
        UpdateRecordUi();
        UpdateInjectInfo();

        _injecting = false;
        UpdateButtons();
        SetStatus(res.Success ? $"✓ {res.Summary}" : $"✗ {res.Summary}", !res.Success);
        if (res.Success)
            SetSimpleStatus($"✓ {mode} injected — {Path.GetFileName(payload)} → {_proc?.Name}" +
                            (mode == "Mono" ? " · the dll is in the recover list now" : ""));
        else
            SetSimpleStatus($"✗ {mode} injection failed — open the Injected tab for the step log", false);

        // pick up (and record) anything that was mapped into the target by the injection
        if (version == _version)
        {
            await RunCaptureAsync();
            RebuildRecoverList();   // a dll that just got mapped becomes recoverable
        }
    }

    private void OnInjectStep(InjectItem item, string message)
    {
        _rec.RecordInjectionStep(item, message);
        if (_injList.SelectedItems.Count > 0 && ReferenceEquals(_injList.SelectedItems[0].Tag, item))
            _injDetail.Text = string.Join(Environment.NewLine, item.Steps);
    }

    // =========================================================================
    // report
    // =========================================================================
    private void SaveReport()
    {
        if (_rec.Items.Count == 0 && _modules.Count == 0)
        {
            MessageBox.Show(this, "Nothing to export yet — select a process and press ● Record.",
                "Dll Dumper", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var sfd = new SaveFileDialog
        {
            Title = "Save report",
            Filter = "Text report (*.txt)|*.txt",
            FileName = $"dll-dumper-{_proc?.Name ?? "process"}-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Dll Dumper report");
            sb.AppendLine($"generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 100));
            if (_proc is { } p)
            {
                sb.AppendLine($"process : {p.Name} (PID {p.Pid}) · {p.Architecture}");
                sb.AppendLine($"exe     : {p.ExePath}");
                sb.AppendLine($"window  : {p.WindowTitle}");
            }
            if (_runtime is { } rt)
            {
                sb.AppendLine($"runtime : {rt.KindName} · {rt.ModuleName} @ 0x{rt.ModuleBase.ToInt64():X} · {rt.Exports.Count} exports");
            }
            sb.AppendLine($"session : {(_rec.IsRecording ? "recording" : "idle")} · {_rec.Items.Count} entries · {_rec.Injections.Count} injections");
            sb.AppendLine();

            sb.AppendLine($"-- MONO ASSEMBLIES ({_assemblies.Count}) " + new string('-', 70));
            foreach (var a in _assemblies)
                sb.AppendLine($"  {a.Name,-40} {a.TypeCount,6} types  {a.MethodCount,7} methods   {a.Path}");
            sb.AppendLine();

            if (_runtime is { Exports.Count: > 0 } rt2)
            {
                sb.AppendLine($"-- RUNTIME EXPORTS ({rt2.Exports.Count}) " + new string('-', 70));
                foreach (var e in rt2.Exports)
                    sb.AppendLine($"  {e.AddressHex,-18} {e.Name}{(e.Forwarded ? "  (forwarded)" : "")}");
                sb.AppendLine();
            }

            sb.AppendLine($"-- FILES MAPPED ({_modules.Count}) " + new string('-', 70));
            foreach (var m in _modules)
                sb.AppendLine($"  {m.BaseHex,-18} {MemoryRegion.FormatSize(m.Size),10}  {m.Path}");
            sb.AppendLine();

            sb.AppendLine($"-- MEMORY MAP ({_regions.Count} regions) " + new string('-', 70));
            foreach (var r in _regions)
                sb.AppendLine($"  {r.BaseHex,-18} {r.SizeText,10}  {r.StateText,-8} {r.ProtectText,-12} {r.TypeText,-8} {r.Owner}");
            sb.AppendLine();

            sb.AppendLine($"-- INJECTIONS ({_rec.Injections.Count}) " + new string('-', 70));
            foreach (var inj in _rec.Injections)
            {
                sb.AppendLine($"  [{inj.Time:HH:mm:ss}] {inj.Mode}  {inj.Payload}  →  {inj.Target}  [{inj.Status}]");
                foreach (var s2 in inj.Steps)
                    sb.AppendLine($"      {s2}");
            }
            sb.AppendLine();

            sb.AppendLine($"-- RECORDED ITEMS ({_rec.Items.Count}) " + new string('-', 70));
            foreach (var it in _rec.Items)
                sb.AppendLine($"  {it.Time:HH:mm:ss.fff}  {it.Kind,-12} {it.Item}  |  {it.Detail}");

            File.WriteAllText(sfd.FileName, sb.ToString());
            SetStatus($"report saved → {sfd.FileName}");
        }
        catch (Exception ex)
        {
            SetStatus("save failed: " + ex.Message, true);
        }
    }

    // =========================================================================
    // misc
    // =========================================================================
    private void SetStatus(string text, bool error = false)
    {
        _statusLabel.Text = text;
        _statusLabel.ForeColor = error ? Color.FromArgb(240, 110, 115) : CDim;
    }
}
