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

async function openPodSwitcher(page, statusText) {
    const status = await waitForStatusItem(page, statusText);
    await status.click();
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

function agentTerminalTab(page, podName) {
    return page
        .locator(".editor-group-container .tabs-container .tab:visible")
        .filter({ hasText: "Rumpelpod:" })
        .filter({ hasText: podName })
        .filter({ hasText: "codex" });
}

function allAgentTerminalTabs(page) {
    return page
        .locator(".editor-group-container .tabs-container .tab:visible")
        .filter({ hasText: "Rumpelpod:" });
}

function shellTerminalTab(page, podName) {
    return page
        .locator(".editor-group-container .tabs-container .tab:visible")
        .filter({ hasText: "Rumpelpod shell:" })
        .filter({ hasText: podName });
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
        await terminal.click();
        await page.keyboard.press("Enter");
        await page.waitForTimeout(500);
    }
    const rendered = await terminalText(terminal);
    assert(rendered.includes("\u203a"), `Codex did not reach its input prompt: ${rendered}`);
}

async function waitForSingleAgentTerminal(page, podName) {
    const deadline = Date.now() + 30_000;
    let labels = [];
    while (Date.now() < deadline) {
        labels = await allAgentTerminalTabs(page).allTextContents();
        if (labels.length === 1 && labels[0].includes(podName)) {
            return agentTerminalTab(page, podName).first();
        }
        await page.waitForTimeout(100);
    }
    throw new Error(
        `active agent did not settle on one ${podName} terminal: ${JSON.stringify(labels)}`,
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

async function assertChatAndDiffGeometry(page, terminal, diffEditor) {
    const terminalBounds = await terminal.boundingBox();
    const diffBounds = await diffEditor.boundingBox();
    assert(terminalBounds, "the agent terminal had no visible bounds");
    assert(diffBounds, "the review diff had no visible bounds");
    assert(
        terminalBounds.x < diffBounds.x,
        `agent chat was not left of the review diff: ${JSON.stringify({ terminalBounds, diffBounds })}`,
    );
    assert(
        terminalBounds.y < diffBounds.y + diffBounds.height &&
            diffBounds.y < terminalBounds.y + terminalBounds.height,
        `agent chat and review diff were not visible together: ${JSON.stringify({ terminalBounds, diffBounds })}`,
    );
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

        await openPodSwitcher(page, "Rumpelpod");
        assert.equal(
            await page.getByRole("treeitem").filter({ hasText: podName }).count(),
            0,
            "the old persistent pod tree was still visible",
        );
        const initialRows = await quickPickRows(page).allTextContents();
        assert(
            initialRows.some((label) => label.includes(podName)),
            `pod switcher omitted ${podName}: ${JSON.stringify(initialRows)}`,
        );
        await selectQuickPick(page, podName);

        const initialTab = await waitForSingleAgentTerminal(page, podName);
        await initialTab.click();
        const initialTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await initialTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await waitForCodexPrompt(page, initialTerminal);
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
        const liveDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        const activeTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await activeTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await assertChatAndDiffGeometry(page, activeTerminal, liveDiff);
        assert.equal(
            await allAgentTerminalTabs(page).count(),
            1,
            "live review refresh created another agent terminal",
        );
        await capture(page, artifacts, "02-live-review.png");

        await openPodSwitcher(page, podName);
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
        const shellTab = shellTerminalTab(page, podName);
        await shellTab.first().waitFor({ state: "visible", timeout: 30_000 });
        const shellTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await shellTerminal.waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await agentTerminalTab(page, podName).count(),
            1,
            "opening a pod shell replaced or duplicated its agent chat",
        );
        await agentTerminalTab(page, podName).first().click();

        const createSwitcher = await openPodSwitcher(page, podName);
        const createPod = createSwitcher.getByRole("button", {
            name: "Create Pod",
            exact: true,
        });
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

        const createdTab = await waitForSingleAgentTerminal(page, createdPodName);
        await createdTab.click();
        const createdTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await createdTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await waitForCodexPrompt(page, createdTerminal);
        await waitForStatusItem(page, createdPodName);
        assert.equal(
            await shellTerminalTab(page, podName).count(),
            0,
            "switching pods kept an auxiliary shell in the default chat layout",
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

        await openPodSwitcher(page, createdPodName);
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

        const switchedTab = await waitForSingleAgentTerminal(page, podName);
        await switchedTab.click();
        const switchedTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await switchedTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await waitForCodexPrompt(page, switchedTerminal, false);
        const switchedDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        await assertChatAndDiffGeometry(page, switchedTerminal, switchedDiff);
        assert.equal(
            await agentTerminalTab(page, createdPodName).count(),
            0,
            "switching pods kept the inactive agent chat open",
        );
        await capture(page, artifacts, "07-switched-review.png");

        await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
        await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
        await waitForStatusItem(page, podName);
        const restoredTab = await waitForSingleAgentTerminal(page, podName);
        await restoredTab.click();
        const restoredTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await restoredTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await waitForCodexPrompt(page, restoredTerminal, false);
        const restoredDiff = await waitForDiff(page, changedFile, originalContent, podContent);
        await assertChatAndDiffGeometry(page, restoredTerminal, restoredDiff);
        assert.equal(
            await agentTerminalTab(page, createdPodName).count(),
            0,
            "reload restored an inactive pod's agent chat",
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
