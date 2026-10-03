package com.nordoptimizer.lsposed.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.nordoptimizer.lsposed.common.ConfigClient;
import com.nordoptimizer.lsposed.common.ConfigManager;
import com.nordoptimizer.lsposed.common.Contract;
import com.nordoptimizer.lsposed.common.HostList;
import com.nordoptimizer.lsposed.common.StatusProvider;

import java.util.ArrayList;
import java.util.List;

/**
 * The manager, written for the person who installed the module from LSPosed and wants three answers: is it
 * on, what has it actually blocked, and which switch does what. Developer evidence (per-hook install tables,
 * self-test) stays available over adb through the status provider instead of cluttering these pages.
 */
public class MainActivity extends Activity {

    private static final int BG = 0xFF0B0D12;
    private static final int TILE = 0xFF10141B;
    private static final int STROKE = 0xFF232A36;
    private static final int TEXT = 0xFFEDF1F7;
    private static final int MUTED = 0xFF9AA3B2;
    private static final int DIM = 0xFF667082;
    private static final int ACCENT = 0xFF4C8DFF;
    private static final int GOOD = 0xFF3ED598;
    private static final int WARN = 0xFFFFB65C;
    private static final int BAD = 0xFFFF6B6B;

    private static final String[] TABS = {"STATUS", "ACTIVITY", "SETTINGS"};

    /**
     * Hook rows the activity feed shows, in end-user language, with the report's s= counter as the number.
     * Everything else in the report (install tables, tunnel plumbing, read-only observers) is measurement,
     * not something the user blocked, so it does not belong in a feed of "what got blocked".
     */
    private static final String[][] BLOCK_LABELS = {
            {"dns", "Tracker lookups refused"},
            {"moose-post", "Telemetry uploads dropped"},
            {"moose-core", "Analytics initialisation blocked"},
            {"moose-ui", "Usage events suppressed"},
            {"moose-debugger", "Debug reports suppressed"},
            {"firebase", "Firebase events suppressed"},
            {"braze", "Braze calls suppressed"},
            {"csat", "Survey prompts suppressed"},
            {"marketing-writes", "Promo content suppressed"},
            {"promo-api", "Promo banners suppressed"},
            {"feedback-dao", "Rating prompts suppressed"},
            {"reminders", "Promo reminders blocked"},
            {"tp-sheet", "Keep-active nag suppressed"},
    };

    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastFingerprint = null;

    private TextView headerState;
    private View headerDot;
    private TextView headerTarget;
    private LinearLayout banner;
    private TextView bannerText;
    private FrameLayout content;
    private final ScrollView[] pages = new ScrollView[TABS.length];
    private final TextView[] tabViews = new TextView[TABS.length];
    private final View[] tabBars = new View[TABS.length];
    private final int[] scrollY = new int[TABS.length];

    private LinearLayout setupCard;
    private TextView tileTrackers, tileTelemetry, tileJunk, tileTunnel;
    private LinearLayout statusEvents;
    private LinearLayout activityList;

    private int activeTab = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ConfigManager.init(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(16), dp(14), dp(16), dp(10));
        setContentView(root);

        buildHeader(root);
        buildTabs(root);
        content = new FrameLayout(this);
        content.addView(pages[0] = buildStatusPage(), match());
        content.addView(pages[1] = buildActivityPage(), match());
        content.addView(pages[2] = buildSettingsPage(), match());
        root.addView(content, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        showTab(0);
        renderReport();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(refresh);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(refresh);
    }

    private final Runnable refresh = new Runnable() {
        @Override
        public void run() {
            renderReport();
            ui.postDelayed(this, 1500L);
        }
    };

    // ---------------------------------------------------------------- header + tabs

    private void buildHeader(LinearLayout root) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(row, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = text("NORD OPTIMIZER", 15, ACCENT, Typeface.DEFAULT_BOLD);
        title.setLetterSpacing(0.08f);
        row.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout pill = new LinearLayout(this);
        pill.setOrientation(LinearLayout.HORIZONTAL);
        pill.setGravity(Gravity.CENTER_VERTICAL);
        pill.setBackground(rounded(TILE, dp(20), STROKE));
        pill.setPadding(dp(9), dp(4), dp(9), dp(4));
        headerDot = new View(this);
        headerDot.setBackground(rounded(MUTED, dp(4), 0));
        pill.addView(headerDot, new LinearLayout.LayoutParams(dp(7), dp(7)));
        ((LinearLayout.LayoutParams) headerDot.getLayoutParams()).setMarginEnd(dp(6));
        headerState = text("WAITING", 11, MUTED, Typeface.DEFAULT_BOLD);
        pill.addView(headerState);
        row.addView(pill);

        headerTarget = text("NordVPN —", 11, DIM, Typeface.DEFAULT);
        root.addView(headerTarget, margins(0, dp(3), 0, 0));

        banner = new LinearLayout(this);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setPadding(dp(11), dp(8), dp(11), dp(8));
        banner.setBackground(rounded(0xFF2A1414, dp(10), 0xFF5C2A2A));
        bannerText = text("", 11, BAD, Typeface.DEFAULT);
        banner.addView(bannerText);
        banner.setVisibility(View.GONE);
        root.addView(banner, margins(0, dp(10), 0, 0));
    }

    private void buildTabs(LinearLayout root) {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER);
        bar.setPadding(0, dp(10), 0, 0);
        for (int i = 0; i < TABS.length; i++) {
            final int index = i;
            LinearLayout tab = new LinearLayout(this);
            tab.setOrientation(LinearLayout.VERTICAL);
            tab.setGravity(Gravity.CENTER_HORIZONTAL);
            TextView t = text(TABS[i], 11, DIM, Typeface.DEFAULT_BOLD);
            t.setLetterSpacing(0.1f);
            t.setPadding(dp(4), dp(6), dp(4), dp(6));
            t.setGravity(Gravity.CENTER);
            tab.addView(t);
            View indicator = new View(this);
            indicator.setBackgroundColor(ACCENT);
            indicator.setVisibility(i == 0 ? View.VISIBLE : View.GONE);
            indicator.setLayoutParams(new LinearLayout.LayoutParams(dp(18), dp(2)));
            tab.addView(indicator);
            tab.setOnClickListener(v -> showTab(index));
            tabViews[i] = t;
            tabBars[i] = indicator;
            bar.addView(tab, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        root.addView(bar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void showTab(int index) {
        activeTab = index;
        for (int i = 0; i < TABS.length; i++) {
            pages[i].setVisibility(i == index ? View.VISIBLE : View.GONE);
            tabViews[i].setTextColor(i == index ? TEXT : DIM);
            tabBars[i].setVisibility(i == index ? View.VISIBLE : View.GONE);
        }
    }

    // ---------------------------------------------------------------- pages

    private ScrollView page() {
        ScrollView s = new ScrollView(this);
        s.setFillViewport(true);
        s.setBackgroundColor(BG);
        return s;
    }

    private LinearLayout column() {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(0, dp(2), 0, dp(12));
        return col;
    }

    private ScrollView buildStatusPage() {
        ScrollView page = page();
        LinearLayout col = column();
        page.addView(col);

        // First-run setup: the one thing this module genuinely needs from the user, spelled out. NordVPN's
        // PairIP protection kills the app ~2 s after launch whenever any LSPosed module is in scope, and
        // LSPosed's per-app "invalidate inline hooks" list is the only fix - it cannot be done from here.
        setupCard = new LinearLayout(this);
        setupCard.setOrientation(LinearLayout.VERTICAL);
        setupCard.setBackground(rounded(0xFF12251C, dp(12), 0xFF2A5C46));
        setupCard.setPadding(dp(12), dp(11), dp(12), dp(11));
        TextView setupTitle = text("ONE-TIME SETUP", 11, GOOD, Typeface.DEFAULT_BOLD);
        setupTitle.setLetterSpacing(0.1f);
        setupCard.addView(setupTitle);
        step(setupCard, "1", "In LSPosed, enable Nord Optimizer with NordVPN as its only scope.");
        step(setupCard, "2", "LSPosed → Settings → Framework → Invalidate inline hooks → tick NordVPN."
                + " NordVPN's tamper protection closes the app seconds after launch without this - every"
                + " module needs it, not just this one.");
        step(setupCard, "3", "Reboot the phone. LSPosed only reads these settings at boot.");
        step(setupCard, "4", "Open NordVPN. This page turns green once the module reports in.");
        col.addView(setupCard, margins(0, dp(10), 0, 0));

        LinearLayout grid = new LinearLayout(this);
        grid.setOrientation(LinearLayout.HORIZONTAL);
        col.addView(grid, margins(0, dp(10), 0, 0));
        grid.addView(tile("TRACKERS BLOCKED", "0"), half());
        grid.addView(tile("TELEMETRY DROPPED", "0"), half());
        grid = new LinearLayout(this);
        grid.setOrientation(LinearLayout.HORIZONTAL);
        col.addView(grid, margins(0, dp(8), 0, 0));
        grid.addView(tile("JUNK PACKETS", "—"), half());
        grid.addView(tile("TUNNEL", "—"), half());
        tileTrackers = tileValues[0];
        tileTelemetry = tileValues[1];
        tileJunk = tileValues[2];
        tileTunnel = tileValues[3];

        col.addView(header("LATEST EVENTS"), margins(0, dp(14), 0, 0));
        statusEvents = new LinearLayout(this);
        statusEvents.setOrientation(LinearLayout.VERTICAL);
        col.addView(statusEvents);
        statusEvents.addView(smallRow("nothing measured yet.", DIM));

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setPadding(0, dp(16), 0, dp(4));
        actions.addView(button("LAUNCH NORDVPN", true, v -> launchTarget()),
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        col.addView(actions);
        return page;
    }

    private void step(LinearLayout parent, String n, String body) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(6), 0, 0);
        row.addView(text(n + ".  ", 11, GOOD, Typeface.DEFAULT_BOLD));
        TextView b = text(body, 11, 0xFFD9E4DA, Typeface.DEFAULT);
        b.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(b);
        parent.addView(row);
    }

    private ScrollView buildActivityPage() {
        ScrollView page = page();
        LinearLayout col = column();
        page.addView(col);
        col.addView(smallRow("what the module has actually blocked or measured since NordVPN last started.",
                DIM), margins(0, dp(2), 0, dp(8)));
        activityList = new LinearLayout(this);
        activityList.setOrientation(LinearLayout.VERTICAL);
        col.addView(activityList);
        activityList.addView(smallRow("nothing yet. Use NordVPN normally; activity shows up here.", DIM));
        return page;
    }

    private ScrollView buildSettingsPage() {
        ScrollView page = page();
        LinearLayout col = column();
        page.addView(col);

        col.addView(header("TELEMETRY"));
        toggle(col, Contract.KEY_BLOCK_TELEMETRY);
        toggle(col, Contract.KEY_KILL_MOOSE);
        toggle(col, Contract.KEY_KILL_SDKS);
        toggle(col, Contract.KEY_MOOSE_UI_EVENTS);
        toggle(col, Contract.KEY_MOOSE_DEBUGGER);

        col.addView(header("NAGS & SURVEYS"));
        toggle(col, Contract.KEY_DEBLOAT_NAGS);

        col.addView(header("CONNECTION"));
        toggle(col, Contract.KEY_JUNK);
        TextView junkValue = row(col, "Junk sizes", junkSummary(), v -> editJunk());
        junkValue.setTag("junk-value");
        toggle(col, Contract.KEY_DEPOISON_DNS);
        toggle(col, Contract.KEY_CLAMP_MTU);
        TextView mtuValue = row(col, "MTU clamp target",
                String.valueOf(ConfigManager.getInt(Contract.KEY_TARGET_MTU)), v -> pickMtu());
        mtuValue.setTag("mtu-value");
        toggle(col, Contract.KEY_OPT_OPENVPN);

        col.addView(header("ADVANCED"));
        toggle(col, Contract.KEY_VERBOSE);
        row(col, "Blocked hosts", "edit sinkhole list", v -> editHosts());

        col.addView(smallRow("every switch reaches NordVPN within a few seconds and survives restarts.",
                DIM), margins(0, dp(12), 0, dp(8)));
        return page;
    }

    // ---------------------------------------------------------------- rendering

    private void renderReport() {
        Bundle report = StatusProvider.lastReport();
        String fingerprint = fingerprintOf(report);
        if (fingerprint.equals(lastFingerprint)) return;
        lastFingerprint = fingerprint;

        for (int i = 0; i < pages.length; i++) {
            scrollY[i] = pages[i].getScrollY();
        }

        if (report == null) {
            headerState.setText("WAITING");
            headerDot.getBackground().setTint(DIM);
            headerTarget.setText("NordVPN — not reporting");
            banner.setVisibility(View.GONE);
            setupCard.setVisibility(View.VISIBLE);
            tileTrackers.setText("0");
            tileTelemetry.setText("0");
            tileJunk.setText(junkTileText());
            tileTunnel.setText("—");
            setRows(statusEvents, smallRow("nothing measured yet.", DIM));
            setRows(activityList, smallRow("finish the setup above, then use NordVPN normally.", DIM));
            restoreScroll();
            return;
        }

        String target = report.getString(Contract.FIELD_TARGET_VERSION);
        boolean reachable = report.getBoolean(ConfigClient.FIELD_PROVIDER_REACHABLE);
        headerState.setText("ATTACHED");
        headerDot.getBackground().setTint(GOOD);
        headerTarget.setText("NordVPN " + target + " · pid " + report.getInt(Contract.FIELD_PID));

        boolean mismatch = target != null && !target.isEmpty() && !Contract.isSupported(target);
        if (mismatch) {
            banner.setVisibility(View.VISIBLE);
            bannerText.setText("Untested against NordVPN " + target + ". Verified: "
                    + Contract.SUPPORTED_TARGET + ". If something stops working after a NordVPN update,"
                    + " this is why.");
        } else if (report.getBoolean(Contract.FIELD_OBSERVE_ONLY)) {
            banner.setVisibility(View.VISIBLE);
            bannerText.setText("Observe-only build: hooks measure but change nothing.");
        } else {
            banner.setVisibility(View.GONE);
        }
        setupCard.setVisibility(View.GONE);

        renderTiles(report);
        renderEvents(report);
        renderActivity(report);

        restoreScroll();
    }

    private void renderTiles(Bundle report) {
        String[] rows = report.getStringArray(Contract.FIELD_ROWS);
        String[] counters = report.getStringArray(Contract.FIELD_COUNTERS);
        int trackers = 0;
        if (counters != null) {
            for (String c : counters) {
                int x = c.lastIndexOf(" x");
                if (x > 0) trackers += parseTail(c.substring(x + 2));
            }
        }
        tileTrackers.setText(String.valueOf(trackers));
        tileTrackers.setTextColor(trackers > 0 ? GOOD : TEXT);

        int dropped = 0;
        if (rows != null) {
            for (String row : rows) {
                String[] p = row.split("\\|", -1);
                if (p.length < 8 || !isBlockedFeature(p[0])) continue;
                dropped += parseTail(p[6].startsWith("s=") ? p[6].substring(2) : p[6]);
            }
        }
        tileTelemetry.setText(String.valueOf(dropped));
        tileTelemetry.setTextColor(dropped > 0 ? GOOD : TEXT);

        String junkFact = null, tunnelFact = null;
        String[] facts = report.getStringArray(Contract.FIELD_FACTS);
        if (facts != null) {
            for (String fact : facts) {
                if (tunnelFact == null && fact.startsWith("TUNNEL|")) tunnelFact = fact;
                if (junkFact == null && fact.startsWith("JUNK|native-bursts|")) junkFact = fact;
            }
        }
        boolean junkOn = ConfigManager.getBoolean(Contract.KEY_JUNK);
        String jt = junkTileText();
        if (junkOn && junkFact != null) {
            jt = junkFact.substring("JUNK|native-bursts|".length()) + " sent";
        }
        tileJunk.setText(jt);
        tileJunk.setTextColor(junkOn ? GOOD : DIM);

        if (tunnelFact != null && tunnelFact.contains("|tun=ok")) {
            tileTunnel.setText(tunnelFact.split("\\|")[1]);
            tileTunnel.setTextColor(GOOD);
        } else if (tunnelFact != null) {
            tileTunnel.setText("failed");
            tileTunnel.setTextColor(BAD);
        } else {
            tileTunnel.setText("—");
            tileTunnel.setTextColor(TEXT);
        }
    }

    private String junkTileText() {
        return ConfigManager.getBoolean(Contract.KEY_JUNK) ? "ON" : "OFF";
    }

    private void renderEvents(Bundle report) {
        String[] facts = report.getStringArray(Contract.FIELD_FACTS);
        LinearLayout out = new LinearLayout(this);
        out.setOrientation(LinearLayout.VERTICAL);
        boolean any = false;
        if (facts != null) {
            for (String fact : facts) {
                String human = humanizeFact(fact);
                if (human == null) continue;
                out.addView(smallRow(human, TEXT), margins(0, 0, 0, dp(6)));
                any = true;
                if (out.getChildCount() >= 4) break;
            }
        }
        if (!any) out.addView(smallRow("nothing measured yet — connect once in NordVPN.", DIM));
        setRows(statusEvents, out);
    }

    /** Facts are the module's measurements; end users get one plain sentence each, dev rows are skipped. */
    private String humanizeFact(String fact) {
        if (fact.startsWith("TUNNEL|")) {
            String[] t = fact.split("\\|");
            String proto = t.length > 1 ? t[1] : "?";
            boolean up = fact.contains("|tun=ok");
            String mtu = valueOf(fact, "builderMtu=");
            String dns = valueOf(fact, "dns=");
            boolean magic = fact.contains("magicDns=yes");
            StringBuilder sb = new StringBuilder();
            sb.append(up ? "Tunnel up" : "Tunnel failed").append(" · ").append(proto);
            if (!"not-set".equals(mtu) && !mtu.isEmpty()) sb.append(" · MTU ").append(mtu);
            if (!dns.isEmpty() && !"server-pushed-or-none".equals(dns)) sb.append(" · DNS ").append(dns);
            if (magic) sb.append(" · MagicDNS");
            return sb.toString();
        }
        if (fact.startsWith("JUNK|native-bursts|")) {
            return fact.substring("JUNK|native-bursts|".length()) + " junk packets sent ahead of handshakes";
        }
        if (fact.startsWith("DNS|DEPOISON|")) {
            String host = between(fact, "DNS|DEPOISON|", "|");
            return "Corrected censored DNS for " + host;
        }
        if (fact.startsWith("DNS|PROBE|")) {
            String host = between(fact, "DNS|PROBE|", "|");
            String system = valueOf(fact, "system=");
            if (isPrivateLiteral(system)) {
                return "Censored DNS detected: " + host + " answers " + system;
            }
            return null;
        }
        return null;
    }

    private void renderActivity(Bundle report) {
        String[] rows = report.getStringArray(Contract.FIELD_ROWS);
        String[] counters = report.getStringArray(Contract.FIELD_COUNTERS);
        LinearLayout out = new LinearLayout(this);
        out.setOrientation(LinearLayout.VERTICAL);
        boolean any = false;

        if (counters != null && counters.length > 0) {
            out.addView(sectionLabel("SINKHOLED DOMAINS"));
            for (String c : counters) {
                out.addView(smallRow(c, ACCENT), margins(0, 0, 0, dp(3)));
                any = true;
            }
        }
        if (rows != null) {
            LinearLayout blocked = new LinearLayout(this);
            blocked.setOrientation(LinearLayout.VERTICAL);
            for (String[] label : BLOCK_LABELS) {
                for (String row : rows) {
                    String[] p = row.split("\\|", -1);
                    if (p.length < 8 || !p[0].equals(label[0])) continue;
                    int s = parseTail(p[6].startsWith("s=") ? p[6].substring(2) : p[6]);
                    if (s <= 0) break;
                    blocked.addView(activityRow(label[1], s));
                    any = true;
                    break;
                }
            }
            if (blocked.getChildCount() > 0) {
                out.addView(sectionLabel("SUPPRESSED"), margins(0, dp(10), 0, dp(2)));
                out.addView(blocked);
            }
        }
        if (!any) {
            out.addView(smallRow("nothing yet. Use NordVPN normally; activity shows up here.", DIM));
        }
        setRows(activityList, out);
    }

    private LinearLayout activityRow(String label, int count) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(4), 0, dp(4));
        TextView l = text(label, 12, TEXT, Typeface.DEFAULT);
        l.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(l);
        row.addView(text("×" + count, 12, GOOD, Typeface.DEFAULT_BOLD));
        return row;
    }

    private TextView sectionLabel(String s) {
        TextView t = text(s, 10, DIM, Typeface.DEFAULT_BOLD);
        t.setLetterSpacing(0.1f);
        return t;
    }

    private void restoreScroll() {
        for (int i = 0; i < pages.length; i++) {
            final ScrollView page = pages[i];
            final int y = scrollY[i];
            page.getViewTreeObserver().addOnGlobalLayoutListener(
                    new android.view.ViewTreeObserver.OnGlobalLayoutListener() {
                        @Override
                        public void onGlobalLayout() {
                            page.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                            page.scrollTo(0, y);
                        }
                    });
        }
    }

    // ---------------------------------------------------------------- settings rows

    private void toggle(LinearLayout parent, String key) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(2), dp(9), dp(2), dp(9));

        TextView label = text(Contract.settingLabel(key), 13, TEXT, Typeface.DEFAULT);
        label.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(label);

        Switch sw = new Switch(this);
        sw.setChecked(ConfigManager.getBoolean(key));
        sw.setOnCheckedChangeListener((v, checked) -> ConfigManager.setBoolean(this, key, checked));
        row.addView(sw);
        row.setOnLongClickListener(v -> {
            expand(Contract.settingLabel(key), Contract.settingSummary(key));
            return true;
        });

        parent.addView(row);
        parent.addView(divider());
    }

    private TextView row(LinearLayout parent, String title, String value, View.OnClickListener onClick) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(2), dp(9), dp(2), dp(9));
        row.setOnClickListener(onClick);

        TextView label = text(title, 13, TEXT, Typeface.DEFAULT);
        label.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(label);
        TextView valueView = text(value, 11, ACCENT, Typeface.DEFAULT);
        row.addView(valueView);

        parent.addView(row);
        parent.addView(divider());
        return valueView;
    }

    // ---------------------------------------------------------------- editors & actions

    private void launchTarget() {
        Intent intent = getPackageManager().getLaunchIntentForPackage(Contract.TARGET_PKG);
        if (intent == null) {
            toast("NordVPN is not installed");
            return;
        }
        startActivity(intent);
    }

    private void editJunk() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), 0);
        final EditText jc = number(ConfigManager.getInt(Contract.KEY_JUNK_COUNT));
        final EditText jmin = number(ConfigManager.getInt(Contract.KEY_JUNK_MIN));
        final EditText jmax = number(ConfigManager.getInt(Contract.KEY_JUNK_MAX));
        box.addView(text("Jc — packets before each handshake (0-20)", 12, MUTED, Typeface.DEFAULT));
        box.addView(jc, margins(0, dp(2), 0, dp(6)));
        box.addView(text("Jmin — smallest packet, bytes", 12, MUTED, Typeface.DEFAULT));
        box.addView(jmin, margins(0, dp(2), 0, dp(6)));
        box.addView(text("Jmax — largest packet, bytes (max 1400)", 12, MUTED, Typeface.DEFAULT));
        box.addView(jmax, margins(0, dp(2), 0, 0));

        new AlertDialog.Builder(this)
                .setTitle("Junk packet sizes")
                .setView(box)
                .setPositiveButton("Save", (d, w) -> {
                    int count = parseOrMinusOne(jc.getText().toString());
                    int min = parseOrMinusOne(jmin.getText().toString());
                    int max = parseOrMinusOne(jmax.getText().toString());
                    if (count < 0 || count > 20) {
                        toast("Jc must be a number between 0 and 20");
                        return;
                    }
                    if (min < 1 || max < min || max > 1400) {
                        toast("Need 1 <= Jmin <= Jmax <= 1400");
                        return;
                    }
                    ConfigManager.setInt(this, Contract.KEY_JUNK_COUNT, count);
                    ConfigManager.setInt(this, Contract.KEY_JUNK_MIN, min);
                    ConfigManager.setInt(this, Contract.KEY_JUNK_MAX, max);
                    findTagged("junk-value").setText(junkSummary());
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private TextView findTagged(String tag) {
        return pages[2].findViewWithTag(tag);
    }

    private String junkSummary() {
        return "Jc=" + ConfigManager.getInt(Contract.KEY_JUNK_COUNT)
                + "  Jmin=" + ConfigManager.getInt(Contract.KEY_JUNK_MIN)
                + "  Jmax=" + ConfigManager.getInt(Contract.KEY_JUNK_MAX);
    }

    private void pickMtu() {
        final int[] sizes = {1200, 1280, 1300, 1360, 1400, 1420, 1450};
        String[] labels = new String[sizes.length];
        for (int i = 0; i < sizes.length; i++) labels[i] = String.valueOf(sizes[i]);
        new AlertDialog.Builder(this)
                .setTitle("MTU clamp target")
                .setItems(labels, (d, which) -> {
                    ConfigManager.setInt(this, Contract.KEY_TARGET_MTU, sizes[which]);
                    findTagged("mtu-value").setText(String.valueOf(sizes[which]));
                })
                .show();
    }

    private void editHosts() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), 0);
        box.addView(text("Extra hosts to block (one per line)", 12, MUTED, Typeface.DEFAULT));
        final EditText extra = input(ConfigManager.getString(Contract.KEY_EXTRA_HOSTS));
        box.addView(extra, margins(0, dp(2), 0, dp(8)));
        box.addView(text("Default hosts to stop blocking (one per line)", 12, MUTED, Typeface.DEFAULT));
        final EditText disabled = input(ConfigManager.getString(Contract.KEY_DISABLED_DEFAULT_HOSTS));
        box.addView(disabled, margins(0, dp(2), 0, dp(8)));
        box.addView(text("Defaults: " + String.join(", ", HostList.DEFAULT_HOSTS), 10, DIM, Typeface.DEFAULT));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(box);
        new AlertDialog.Builder(this)
                .setTitle("Sinkhole host list")
                .setView(scroll)
                .setPositiveButton("Save", (d, w) -> saveHosts(extra.getText().toString(),
                        disabled.getText().toString()))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void saveHosts(String extraRaw, String disabledRaw) {
        List<String> risky = new ArrayList<>();
        for (String host : extraRaw.split("[,;\\s]+")) {
            String h = host.trim().toLowerCase();
            if (!h.isEmpty() && HostList.isFunctional(h) && !risky.contains(h)) risky.add(h);
        }
        if (risky.isEmpty()) {
            commitHosts(extraRaw, disabledRaw);
            return;
        }
        // Warn rather than veto: it is the user's list, but blocking one of these breaks login, the server
        // list, pricing or push, and the failure looks like a VPN bug rather than a module bug.
        new AlertDialog.Builder(this)
                .setTitle("These hosts are not telemetry")
                .setMessage(String.join(", ", risky)
                        + "\n\nBlocking them can break sign-in, the server list, plans, Threat Protection or"
                        + " notifications. Block anyway?")
                .setPositiveButton("Block anyway", (d, w) -> commitHosts(extraRaw, disabledRaw))
                .setNegativeButton("Remove them", null)
                .show();
    }

    private void commitHosts(String extraRaw, String disabledRaw) {
        ConfigManager.setString(this, Contract.KEY_EXTRA_HOSTS, extraRaw == null ? "" : extraRaw.trim());
        ConfigManager.setString(this, Contract.KEY_DISABLED_DEFAULT_HOSTS,
                disabledRaw == null ? "" : disabledRaw.trim());
        toast("Saved. NordVPN picks this up within a few seconds.");
        lastFingerprint = null;
        renderReport();
    }

    private void expand(String title, String message) {
        new AlertDialog.Builder(this).setTitle(title).setMessage(message).show();
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    // ---------------------------------------------------------------- parsing

    /** Everything the page renders, cheaply comparable: unchanged report, unchanged page, no rebuild. */
    private static String fingerprintOf(Bundle report) {
        if (report == null) return "none";
        StringBuilder sb = new StringBuilder(512);
        sb.append(report.getInt(Contract.FIELD_PID)).append('|')
                .append(report.getLong(Contract.FIELD_ATTACHED_AT)).append('|')
                .append(report.getString(Contract.FIELD_DIGEST)).append('|')
                .append(report.getBoolean(ConfigClient.FIELD_PROVIDER_REACHABLE)).append('|')
                .append(report.getBoolean(Contract.FIELD_OBSERVE_ONLY));
        for (String[] array : new String[][]{
                report.getStringArray(Contract.FIELD_ROWS),
                report.getStringArray(Contract.FIELD_HOSTS),
                report.getStringArray(Contract.FIELD_COUNTERS),
                report.getStringArray(Contract.FIELD_FACTS)}) {
            sb.append('|');
            if (array != null) sb.append(String.join("\n", array));
        }
        return sb.toString();
    }

    private static boolean isBlockedFeature(String id) {
        for (String[] label : BLOCK_LABELS) {
            if (label[0].equals(id)) return true;
        }
        return false;
    }

    private static int parseTail(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String valueOf(String fact, String key) {
        int i = fact.indexOf(key);
        if (i < 0) return "";
        int end = fact.indexOf('|', i);
        return end < 0 ? fact.substring(i + key.length()) : fact.substring(i + key.length(), end);
    }

    private static String between(String s, String prefix, String terminator) {
        int i = s.indexOf(prefix);
        if (i < 0) return "";
        int start = i + prefix.length();
        int end = s.indexOf(terminator, start);
        return end < 0 ? s.substring(start) : s.substring(start, end);
    }

    private static boolean isPrivateLiteral(String addr) {
        if (addr.isEmpty() || "none".equals(addr) || addr.startsWith("err:")) return false;
        return addr.startsWith("10.") || addr.startsWith("192.168.") || addr.startsWith("127.")
                || addr.startsWith("169.254.") || addr.startsWith("172.16.") || addr.startsWith("172.17.")
                || addr.startsWith("172.18.") || addr.startsWith("172.19.") || addr.startsWith("172.2")
                || addr.startsWith("172.30.") || addr.startsWith("172.31.");
    }

    // ---------------------------------------------------------------- view helpers

    private TextView header(String s) {
        TextView t = text(s, 10, DIM, Typeface.DEFAULT_BOLD);
        t.setLetterSpacing(0.12f);
        return t;
    }

    private TextView smallRow(String s, int color) {
        return text(s, 11, color, Typeface.DEFAULT);
    }

    private TextView[] tileValues = new TextView[4];
    private int tileIndex = 0;

    private View tile(String label, String value) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(rounded(TILE, dp(12), STROKE));
        box.setPadding(dp(12), dp(10), dp(12), dp(10));
        TextView v = text(value, 17, TEXT, Typeface.DEFAULT_BOLD);
        tileValues[tileIndex++] = v;
        box.addView(v);
        TextView l = text(label, 9, DIM, Typeface.DEFAULT_BOLD);
        l.setLetterSpacing(0.1f);
        box.addView(l, margins(0, dp(1), 0, 0));
        return box;
    }

    private View button(String label, boolean primary, View.OnClickListener onClick) {
        TextView b = text(label, 12, primary ? 0xFFFFFFFF : TEXT, Typeface.DEFAULT_BOLD);
        b.setGravity(Gravity.CENTER);
        b.setBackground(rounded(primary ? 0xFF1E3A66 : TILE, dp(10), primary ? ACCENT : STROKE));
        b.setPadding(dp(12), dp(11), dp(12), dp(11));
        b.setOnClickListener(onClick);
        return b;
    }

    private View divider() {
        View v = new View(this);
        v.setBackgroundColor(0xFF1A1E27);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));
        return v;
    }

    private void setRows(LinearLayout container, View replacement) {
        container.removeAllViews();
        container.addView(replacement);
    }

    private LinearLayout.LayoutParams margins(int l, int t, int r, int b) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(l, t, r, b);
        return lp;
    }

    private LinearLayout.LayoutParams half() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(3), 0, dp(3), 0);
        return lp;
    }

    private FrameLayout.LayoutParams match() {
        return new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
    }

    private GradientDrawable rounded(int color, int radius, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        d.setStroke(dp(1), stroke);
        return d;
    }

    private TextView text(String content, int size, int color, Typeface face) {
        TextView tv = new TextView(this);
        tv.setText(content);
        tv.setTextSize(size);
        tv.setTypeface(face);
        tv.setTextColor(color);
        return tv;
    }

    private EditText number(int value) {
        EditText e = new EditText(this);
        e.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        e.setTextSize(14);
        e.setTextColor(TEXT);
        e.setText(String.valueOf(value));
        return e;
    }

    private EditText input(String value) {
        EditText e = new EditText(this);
        e.setMinLines(2);
        e.setGravity(Gravity.TOP);
        e.setTextSize(13);
        e.setTextColor(TEXT);
        e.setHintTextColor(DIM);
        e.setText(value == null ? "" : value);
        return e;
    }

    private static int parseOrMinusOne(String raw) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
