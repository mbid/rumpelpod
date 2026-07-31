// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createRequire } = require("node:module");

const requireFromExtension = createRequire(path.join(process.cwd(), "package.json"));
const { chromium } = requireFromExtension("@playwright/test");

const REFERENCE_IMAGES = [
    "01-default-chat.png",
    "02-live-review.png",
    "03-pod-switcher.png",
    "04-agent-picker.png",
    "05-pod-name.png",
    "06-created-chat.png",
    "07-switched-review.png",
    "08-restored-chat.png",
];

function requiredEnvironment(name) {
    const value = process.env[name];
    assert(value, `${name} is required`);
    return value;
}

async function capture(page, artifacts, name) {
    fs.mkdirSync(artifacts, { recursive: true });
    const artifactPath = path.join(artifacts, name);
    await page.screenshot({
        path: artifactPath,
        fullPage: true,
    });
}

function publishReferenceImages(artifacts, referenceImages) {
    if (!referenceImages) {
        return;
    }
    for (const name of REFERENCE_IMAGES) {
        const artifact = path.join(artifacts, name);
        assert(fs.existsSync(artifact), `successful browser run omitted ${artifact}`);
    }
    fs.mkdirSync(referenceImages, { recursive: true });
    for (const name of REFERENCE_IMAGES) {
        fs.copyFileSync(path.join(artifacts, name), path.join(referenceImages, name));
    }
}

function statusItem(page, text) {
    return page.locator(".statusbar-item").filter({ hasText: text }).first();
}

async function waitForStatusItem(page, text) {
    const status = statusItem(page, text);
    await status.waitFor({ state: "visible", timeout: 30_000 });
    return status;
}

async function openRumpelpodView(page) {
    const action = page.locator('.activitybar a[aria-label="Rumpelpod"]');
    await action.waitFor({ state: "visible", timeout: 30_000 });
    await action.click();
    const sidebar = page.locator(".part.sidebar:visible");
    await sidebar.waitFor({ state: "visible", timeout: 30_000 });
    await sidebar
        .locator(".composite.title")
        .filter({ hasText: "Rumpelpod" })
        .waitFor({ state: "visible", timeout: 30_000 });
    return sidebar;
}

async function openPodSwitcher(page) {
    const switchPod = page.locator('.part.sidebar:visible [aria-label="Switch Pod"]').first();
    await switchPod.waitFor({ state: "visible", timeout: 30_000 });
    await switchPod.click();
    const widget = page.locator(".quick-input-widget:visible");
    await widget.waitFor({ state: "visible", timeout: 30_000 });
    return widget;
}

function quickPickRows(page) {
    return page.locator(".quick-input-widget:visible .quick-input-list .monaco-list-row");
}

async function quickPickRow(page, label) {
    const rows = quickPickRows(page);
    await rows.first().waitFor({ state: "visible", timeout: 30_000 });
    const row = rows.filter({ hasText: label });
    await row.first().waitFor({ state: "visible", timeout: 30_000 });
    return row.first();
}

async function selectQuickPick(page, label) {
    const row = await quickPickRow(page, label);
    await row.click();
    if (await row.isVisible()) {
        await page.keyboard.press("Enter");
    }
    await row.waitFor({ state: "hidden", timeout: 30_000 });
}

async function waitForQuickPickLabels(page, labels) {
    const deadline = Date.now() + 30_000;
    let rendered = "";
    while (Date.now() < deadline) {
        rendered = (await quickPickRows(page).allTextContents()).join("\n");
        if (labels.every((label) => rendered.includes(label))) {
            return rendered;
        }
        await page.waitForTimeout(100);
    }
    throw new Error(`quick pick omitted ${labels.join(", ")}: ${rendered}`);
}

function allAgentTerminalTabs(page) {
    return page
        .locator(".editor-group-container .tabs-container .tab:visible")
        .filter({ hasText: "Rumpelpod:" });
}

async function terminalText(terminal) {
    const renderedText = terminal.locator(".xterm-accessibility-tree, .xterm-rows");
    if (!(await renderedText.count())) {
        return "";
    }
    const lines = await renderedText.allTextContents();
    return lines.join("\n").replace(/\u00a0/g, " ");
}

async function waitForTerminalText(page, terminal, needle, description, timeout = 90_000) {
    const deadline = Date.now() + timeout;
    let rendered = "";
    while (Date.now() < deadline) {
        rendered = await terminalText(terminal);
        if (rendered.includes(needle)) {
            return rendered;
        }
        await page.waitForTimeout(250);
    }
    throw new Error(`${description} did not appear in the terminal; rendered text: ${rendered}`);
}

async function waitForTerminalTextAbsent(page, terminal, needle, description, timeout = 30_000) {
    const deadline = Date.now() + timeout;
    let rendered = "";
    while (Date.now() < deadline) {
        rendered = await terminalText(terminal);
        if (!rendered.includes(needle)) {
            return rendered;
        }
        await page.waitForTimeout(100);
    }
    throw new Error(`${description} remained in the terminal; rendered text: ${rendered}`);
}

async function focusTerminalInput(terminal) {
    const input = terminal.locator("textarea.xterm-helper-textarea");
    await input.waitFor({ state: "attached", timeout: 30_000 });
    await input.focus();
}

async function typeInTerminal(page, terminal, value) {
    await focusTerminalInput(terminal);
    await page.keyboard.type(value);
}

async function pressInTerminal(page, terminal, key) {
    await focusTerminalInput(terminal);
    await page.keyboard.press(key);
}

async function waitForCodexPrompt(page, terminal, requireStartupOutput = true) {
    const marker = requireStartupOutput ? "WARNING: proceeding" : "OpenAI Codex";
    const description = requireStartupOutput ? "Codex startup output" : "restored Codex session";
    await waitForTerminalText(page, terminal, marker, description);
    for (let attempt = 0; attempt < 12; attempt += 1) {
        const rendered = await terminalText(terminal);
        for (const failure of ["error: server error", "command not found", "No such file or directory"]) {
            assert(!rendered.includes(failure), `Codex terminal reported ${failure}: ${rendered}`);
        }
        if (rendered.includes("\u203a")) {
            return;
        }
        await pressInTerminal(page, terminal, "Enter");
        await page.waitForTimeout(500);
    }
    const rendered = await terminalText(terminal);
    assert(rendered.includes("\u203a"), `Codex did not reach its input prompt: ${rendered}`);
}

async function waitForAgentFrame(page) {
    const deadline = Date.now() + 30_000;
    let frameUrls = [];
    while (Date.now() < deadline) {
        const frames = page.frames();
        frameUrls = frames.map((frame) => frame.url());
        for (const frame of frames) {
            if (!frame.url().includes("/fake.html")) {
                continue;
            }
            const body = frame.locator("body[data-rumpelpod-agent-view='true']");
            try {
                if (await body.count()) {
                    return frame;
                }
            } catch (_error) {
                // The webview can navigate while VS Code restores the sidebar.
            }
        }
        await page.waitForTimeout(100);
    }
    throw new Error(`Rumpelpod agent webview did not load; frames: ${JSON.stringify(frameUrls)}`);
}

async function waitForAgentView(page, podName, agent = "codex") {
    const frame = await waitForAgentFrame(page);
    const body = frame.locator("body[data-rumpelpod-agent-view='true']");
    const deadline = Date.now() + 30_000;
    let attributes = {};
    while (Date.now() < deadline) {
        attributes = {
            agent: await body.getAttribute("data-rumpelpod-agent"),
            pod: await body.getAttribute("data-rumpelpod-pod"),
            state: await body.getAttribute("data-rumpelpod-state"),
        };
        if (
            attributes.agent === agent &&
            attributes.pod === podName &&
            attributes.state === "running"
        ) {
            break;
        }
        await page.waitForTimeout(100);
    }
    assert.deepEqual(
        attributes,
        { agent, pod: podName, state: "running" },
        `agent webview did not settle on ${podName}/${agent}`,
    );
    const terminals = frame.locator("#terminal .xterm:visible");
    await terminals.first().waitFor({ state: "visible", timeout: 30_000 });
    const session = await body.getAttribute("data-rumpelpod-session");
    assert(session, "agent webview did not expose its active terminal session");
    const renderedDeadline = Date.now() + 30_000;
    let renderedSession = "";
    while (Date.now() < renderedDeadline) {
        renderedSession =
            (await body.getAttribute("data-rumpelpod-rendered-session")) ?? "";
        if (renderedSession === session) {
            break;
        }
        await page.waitForTimeout(100);
    }
    assert.equal(renderedSession, session, `session ${session} produced no rendered output`);
    assert.equal(await terminals.count(), 1, "agent webview rendered more than one xterm");
    assert.equal(
        await allAgentTerminalTabs(page).count(),
        0,
        "the embedded agent was also opened as a native editor terminal",
    );
    return { body, frame, terminal: terminals.first() };
}

async function waitForAgentRepositoryState(page, view, repositoryState) {
    const deadline = Date.now() + 30_000;
    let rendered = "";
    while (Date.now() < deadline) {
        rendered = (await view.body.getAttribute("data-rumpelpod-repository-state")) ?? "";
        if (rendered === repositoryState) {
            return;
        }
        await page.waitForTimeout(100);
    }
    throw new Error(
        `agent view did not update repository state to ${repositoryState}; rendered: ${rendered}`,
    );
}

async function openCodeServer(page, url) {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const passwordInput = page.locator('input[name="password"]');
    assert.equal(await passwordInput.count(), 0, "code-server unexpectedly required a password");
    await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
}

function shellQuote(value) {
    return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function runPodCommit(rumpel, repoRoot, home, socket, podName, changedFile, podContent) {
    const script = [
        `printf '%s\\n' ${shellQuote(podContent)} > ${shellQuote(changedFile)}`,
        `git add -- ${shellQuote(changedFile)}`,
        "git commit --no-verify -m 'Change browser diff fixture'",
        "git rev-parse HEAD",
    ].join(" && ");
    const environment = {
        ...process.env,
        HOME: home,
        RUMPELPOD_DAEMON_SOCKET: socket,
    };
    const commit = spawnSync(
        rumpel,
        ["enter", "--create", podName, "--", "sh", "-c", script],
        {
            cwd: repoRoot,
            encoding: "utf8",
            env: environment,
            maxBuffer: 10 * 1024 * 1024,
        },
    );
    assert.equal(
        commit.status,
        0,
        `committing inside ${podName} failed:\nstdout:\n${commit.stdout}\nstderr:\n${commit.stderr}`,
    );
    const commits = commit.stdout.match(/[0-9a-f]{40}/g) ?? [];
    assert(commits.length > 0, `pod commit did not report its HEAD: ${commit.stdout}`);
    const podHead = commits.at(-1);
    const hostRef = spawnSync(
        "git",
        ["rev-parse", "--verify", `refs/rumpelpod/${podName}`],
        {
            cwd: repoRoot,
            encoding: "utf8",
            env: environment,
        },
    );
    assert.equal(
        hostRef.status,
        0,
        `host did not receive the ${podName} review ref:\n${hostRef.stderr}`,
    );
    assert.equal(hostRef.stdout.trim(), podHead, "host review ref did not match the pod commit");
}

async function waitForStatusRepository(page, podName, repositoryState) {
    const deadline = Date.now() + 30_000;
    let rendered = "";
    while (Date.now() < deadline) {
        const status = await waitForStatusItem(page, podName);
        rendered = (await status.textContent()) || "";
        if (rendered.includes(repositoryState)) {
            return;
        }
        await page.waitForTimeout(200);
    }
    throw new Error(
        `status did not update to repository state ${repositoryState}; rendered text: ${rendered}`,
    );
}

async function waitForDiff(page, changedFile, originalContent, podContent) {
    const diffEditor = page.locator(".monaco-diff-editor:visible").last();
    await diffEditor.waitFor({ state: "visible", timeout: 30_000 });
    await diffEditor
        .locator(".view-line")
        .filter({ hasText: originalContent })
        .first()
        .waitFor({ state: "visible", timeout: 30_000 });
    await diffEditor
        .locator(".view-line")
        .filter({ hasText: podContent })
        .first()
        .waitFor({ state: "visible", timeout: 30_000 });
    const rendered = (await diffEditor.locator(".view-lines").allTextContents())
        .join("\n")
        .replace(/\u00a0/g, " ");
    assert(
        rendered.includes(originalContent),
        `diff editor did not render original content; rendered text: ${rendered}`,
    );
    assert(
        rendered.includes(podContent),
        `diff editor did not render pod content; rendered text: ${rendered}`,
    );
    const activeTabs = await page.locator(".tab.active").allTextContents();
    assert(
        activeTabs.some((label) => label.includes(changedFile)),
        `active diff tab did not name ${changedFile}: ${JSON.stringify(activeTabs)}`,
    );
    return diffEditor;
}

async function assertSidebarAndDiffGeometry(page, terminal, diffEditor) {
    const sidebar = page.locator(".part.sidebar:visible");
    const sidebarBounds = await sidebar.boundingBox();
    const terminalBounds = await terminal.boundingBox();
    const diffBounds = await diffEditor.boundingBox();
    assert(sidebarBounds, "the Rumpelpod sidebar had no visible bounds");
    assert(terminalBounds, "the agent terminal had no visible bounds");
    assert(diffBounds, "the review diff had no visible bounds");
    assert(
        sidebarBounds.x + sidebarBounds.width <= diffBounds.x + 1,
        `the review diff overlapped the Rumpelpod sidebar: ${JSON.stringify({ sidebarBounds, diffBounds })}`,
    );
    assert(
        terminalBounds.x >= sidebarBounds.x &&
            terminalBounds.x + terminalBounds.width <= sidebarBounds.x + sidebarBounds.width + 1,
        `agent xterm was not contained by the sidebar: ${JSON.stringify({ sidebarBounds, terminalBounds })}`,
    );
}

async function waitForNativeShellPanel(page, podName) {
    const panel = page.locator(".part.panel:visible");
    await panel.waitFor({ state: "visible", timeout: 30_000 });
    const terminal = panel.locator(".terminal-wrapper .xterm:visible").first();
    await terminal.waitFor({ state: "visible", timeout: 30_000 });
    await waitForTerminalText(
        page,
        terminal,
        `Opening a shell in rumpelpod ${podName}`,
        `native shell for ${podName}`,
    );
    assert.equal(
        await page.locator(".terminal-editor .xterm:visible").count(),
        0,
        "pod shell opened as an editor instead of in the native terminal panel",
    );
    return terminal;
}

async function closeNativeShell(page, terminal) {
    await typeInTerminal(page, terminal, "exit");
    await pressInTerminal(page, terminal, "Enter");
    await terminal.waitFor({ state: "hidden", timeout: 30_000 });
}

async function main() {
    const url = requiredEnvironment("RUMPELPOD_VSCODE_URL");
    const podName = requiredEnvironment("RUMPELPOD_VSCODE_POD");
    const createdPodName = requiredEnvironment("RUMPELPOD_VSCODE_CREATED_POD");
    const changedFile = requiredEnvironment("RUMPELPOD_VSCODE_CHANGED_FILE");
    const originalContent = requiredEnvironment("RUMPELPOD_VSCODE_ORIGINAL_CONTENT");
    const podContent = requiredEnvironment("RUMPELPOD_VSCODE_POD_CONTENT");
    const repoRoot = requiredEnvironment("RUMPELPOD_VSCODE_REPO_ROOT");
    const rumpel = requiredEnvironment("RUMPELPOD_VSCODE_RUMPEL");
    const socket = requiredEnvironment("RUMPELPOD_DAEMON_SOCKET");
    const home = requiredEnvironment("RUMPELPOD_VSCODE_HOME");
    const executablePath = requiredEnvironment("RUMPELPOD_CHROMIUM");
    const artifacts = requiredEnvironment("RUMPELPOD_VSCODE_ARTIFACTS");
    const referenceImages = process.env.RUMPELPOD_VSCODE_REFERENCE_IMAGES;

    const browser = await chromium.launch({
        executablePath,
        headless: true,
        args: ["--no-sandbox", "--disable-dev-shm-usage", "--force-renderer-accessibility"],
    });
    fs.mkdirSync(artifacts, { recursive: true });
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    const page = await context.newPage();
    const browserErrors = [];
    page.on("console", (message) => {
        process.stderr.write(`[BROWSER ${message.type()}] ${message.text()}\n`);
    });
    page.on("pageerror", (error) => {
        process.stderr.write(`[BROWSER ERROR] ${error.stack || error.message}\n`);
        browserErrors.push(error);
    });

    try {
        await openCodeServer(page, url);

        await openRumpelpodView(page);
        const initialSwitcher = page.locator(".quick-input-widget:visible");
        await initialSwitcher.waitFor({ state: "visible", timeout: 30_000 });
        const initialRows = await quickPickRows(page).allTextContents();
        assert(
            initialRows.some((label) => label.includes(podName)),
            `pod switcher omitted ${podName}: ${JSON.stringify(initialRows)}`,
        );
        await selectQuickPick(page, podName);

        const initialView = await waitForAgentView(page, podName);
        await waitForCodexPrompt(page, initialView.terminal);
        await typeInTerminal(page, initialView.terminal, "browser-input-probe");
        await waitForTerminalText(
            page,
            initialView.terminal,
            "browser-input-probe",
            "input sent through the embedded xterm",
        );
        await pressInTerminal(page, initialView.terminal, "Control+U");
        await waitForTerminalTextAbsent(
            page,
            initialView.terminal,
            "browser-input-probe",
            "cleared input sent through the embedded xterm",
        );
        assert.equal(
            await page.locator(".monaco-diff-editor:visible").count(),
            0,
            "a clean pod opened a diff before its live commit",
        );
        assert.equal(
            await page.locator(".tab:visible").filter({ hasText: "-review.txt" }).count(),
            0,
            "a clean pod opened a synthetic review document",
        );
        await capture(page, artifacts, "01-default-chat.png");

        runPodCommit(rumpel, repoRoot, home, socket, podName, changedFile, podContent);

        await waitForStatusRepository(page, podName, "ahead 1");
        await waitForAgentRepositoryState(page, initialView, "ahead 1");
        const liveDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        const liveView = await waitForAgentView(page, podName);
        await assertSidebarAndDiffGeometry(page, liveView.terminal, liveDiff);
        assert.equal(
            await liveView.frame.locator("#terminal .xterm:visible").count(),
            1,
            "live review refresh created another embedded agent terminal",
        );
        await capture(page, artifacts, "02-live-review.png");

        await openPodSwitcher(page);
        const rowsAfterCommit = await quickPickRows(page).allTextContents();
        assert(
            rowsAfterCommit.some(
                (label) =>
                    label.includes(podName) &&
                    label.includes("Codex") &&
                    label.includes("ahead 1"),
            ),
            `pod switcher omitted live agent/repository state: ${JSON.stringify(rowsAfterCommit)}`,
        );
        await capture(page, artifacts, "03-pod-switcher.png");

        const reviewPodRow = await quickPickRow(page, podName);
        await reviewPodRow.hover();
        const openShell = reviewPodRow.getByRole("button", {
            name: "Open Pod Shell",
            exact: true,
        });
        await openShell.waitFor({ state: "visible", timeout: 30_000 });
        await openShell.click();
        const shellTerminal = await waitForNativeShellPanel(page, podName);
        const viewWhileShellIsOpen = await waitForAgentView(page, podName);
        await waitForCodexPrompt(page, viewWhileShellIsOpen.terminal, false);
        assert.equal(
            await viewWhileShellIsOpen.frame.locator("#terminal .xterm:visible").count(),
            1,
            "opening a pod shell replaced or duplicated its agent chat",
        );
        await closeNativeShell(page, shellTerminal);

        const createPod = page.locator('.part.sidebar:visible [aria-label="Create Pod"]').first();
        await createPod.waitFor({ state: "visible", timeout: 30_000 });
        await createPod.click();
        const agentLabels = await waitForQuickPickLabels(page, ["Claude Code", "Codex"]);
        assert(agentLabels.includes("Claude Code"), `agent picker omitted Claude: ${agentLabels}`);
        assert(agentLabels.includes("Codex"), `agent picker omitted Codex: ${agentLabels}`);
        await capture(page, artifacts, "04-agent-picker.png");
        await selectQuickPick(page, "Codex");

        const podNameInput = page.locator(".quick-input-widget:visible input");
        await podNameInput.waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await podNameInput.getAttribute("placeholder"),
            "feature-name",
            "pod creation did not advance to the name input",
        );
        await podNameInput.fill(createdPodName);
        await capture(page, artifacts, "05-pod-name.png");
        await page.keyboard.press("Enter");

        const createdView = await waitForAgentView(page, createdPodName);
        await waitForCodexPrompt(page, createdView.terminal);
        await waitForStatusItem(page, createdPodName);
        assert.equal(
            await page.locator(".part.panel:visible .terminal-wrapper .xterm:visible").count(),
            0,
            "creating a pod kept the closed auxiliary shell alive",
        );
        assert.equal(
            await page.locator(".monaco-diff-editor:visible").count(),
            0,
            "creating a clean pod left the previous pod's diff visible",
        );
        assert.equal(
            await page.locator(".tab:visible").filter({ hasText: "-review.txt" }).count(),
            0,
            "creating a pod opened a synthetic review document",
        );
        await capture(page, artifacts, "06-created-chat.png");

        await openPodSwitcher(page);
        const listedPods = await quickPickRows(page).allTextContents();
        assert(
            listedPods.some((label) => label.includes(podName)),
            `existing pod disappeared from the switcher: ${JSON.stringify(listedPods)}`,
        );
        assert(
            listedPods.some((label) => label.includes(createdPodName)),
            `created pod was not listed in the switcher: ${JSON.stringify(listedPods)}`,
        );
        await selectQuickPick(page, podName);

        const switchedView = await waitForAgentView(page, podName);
        await waitForCodexPrompt(page, switchedView.terminal, false);
        const switchedDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        await assertSidebarAndDiffGeometry(page, switchedView.terminal, switchedDiff);
        assert.equal(
            await switchedView.body.getAttribute("data-rumpelpod-pod"),
            podName,
            "switching pods left the inactive agent in the embedded terminal",
        );
        await capture(page, artifacts, "07-switched-review.png");

        const reloadMarker = "reload-session-marker";
        await typeInTerminal(page, switchedView.terminal, reloadMarker);
        await waitForTerminalText(
            page,
            switchedView.terminal,
            reloadMarker,
            "unsent input before browser reload",
        );

        await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
        await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
        await page
            .locator(".part.sidebar:visible .composite.title")
            .filter({ hasText: "Rumpelpod" })
            .waitFor({ state: "visible", timeout: 30_000 });
        await page
            .locator('.activitybar a[aria-label="Rumpelpod"]')
            .waitFor({ state: "visible", timeout: 30_000 });
        await waitForStatusItem(page, podName);
        const restoredView = await waitForAgentView(page, podName);
        await waitForTerminalText(
            page,
            restoredView.terminal,
            reloadMarker,
            "the attached Codex session after browser reload",
        );
        await pressInTerminal(page, restoredView.terminal, "Control+U");
        await waitForTerminalTextAbsent(
            page,
            restoredView.terminal,
            reloadMarker,
            "cleared input after browser reload",
        );
        await waitForCodexPrompt(page, restoredView.terminal, false);
        const restoredDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        await assertSidebarAndDiffGeometry(page, restoredView.terminal, restoredDiff);
        assert.equal(
            await restoredView.frame.locator("#terminal .xterm:visible").count(),
            1,
            "reload restored more than one embedded agent terminal",
        );
        await capture(page, artifacts, "08-restored-chat.png");
        assert.equal(
            browserErrors.length,
            0,
            `browser page errors occurred: ${browserErrors.map((error) => error.message).join("; ")}`,
        );
        publishReferenceImages(artifacts, referenceImages);
    } catch (error) {
        fs.mkdirSync(artifacts, { recursive: true });
        try {
            await page.screenshot({
                path: path.join(artifacts, "failure.png"),
                fullPage: true,
            });
        } catch (screenshotError) {
            process.stderr.write(`capturing failure screenshot failed: ${screenshotError}\n`);
        }
        throw error;
    } finally {
        try {
            await context.tracing.stop({ path: path.join(artifacts, "trace.zip") });
            process.stderr.write(`Playwright artifacts: ${artifacts}\n`);
        } catch (traceError) {
            process.stderr.write(`capturing Playwright trace failed: ${traceError}\n`);
        }
        await browser.close();
    }
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exitCode = 1;
});
