// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const requireFromExtension = createRequire(path.join(process.cwd(), "package.json"));
const { chromium } = requireFromExtension("@playwright/test");

function requiredEnvironment(name) {
    const value = process.env[name];
    assert(value, `${name} is required`);
    return value;
}

async function openRumpelpodView(page) {
    await page.keyboard.press("F1");
    const quickInput = page.locator(".quick-input-widget input");
    await quickInput.waitFor({ state: "visible" });
    await quickInput.fill(">Rumpelpod");

    const commands = page.locator(".quick-input-list .monaco-list-row");
    await commands.first().waitFor({ state: "visible" });
    const count = await commands.count();
    for (let index = 0; index < count; index += 1) {
        const command = commands.nth(index);
        const label = (await command.textContent()) || "";
        if (/focus.*pods|pods.*focus|open.*rumpelpod|rumpelpod.*open/i.test(label)) {
            await command.click();
            return;
        }
    }

    const labels = await commands.allTextContents();
    await page.keyboard.press("Escape");
    const labelledActivityItem = page.locator('.activitybar [aria-label*="Rumpelpod"]');
    if (await labelledActivityItem.count()) {
        await labelledActivityItem.first().click();
        return;
    }
    throw new Error(`no Rumpelpod view command or activity item was available: ${JSON.stringify(labels)}`);
}

async function locateTreeItem(page, text) {
    const exact = page.getByRole("treeitem", { name: text, exact: true });
    if (await exact.count()) {
        return exact.first();
    }
    const matching = page.getByRole("treeitem").filter({ hasText: text });
    await matching.first().waitFor({ state: "visible" });
    return matching.first();
}

async function locatePodOrReportError(page, podName) {
    const pod = page.getByRole("treeitem").filter({ hasText: podName });
    const failure = page.getByRole("treeitem").filter({ hasText: "Could not list pods" });
    await pod.or(failure).first().waitFor({ state: "visible" });
    if (await pod.count()) {
        return pod.first();
    }

    const item = failure.first();
    await item.hover();
    await page.waitForTimeout(500);
    const hoverText = await page.locator(".monaco-hover").allTextContents();
    const markup = await item.evaluate((element) => element.outerHTML);
    throw new Error(
        `extension could not list pods; hover: ${JSON.stringify(hoverText)}; item: ${markup}`,
    );
}

async function expandTreeItem(item) {
    if ((await item.getAttribute("aria-expanded")) === "true") {
        return;
    }
    const twistie = item.locator(".monaco-tl-twistie");
    if (await twistie.count()) {
        await twistie.first().click();
    } else {
        await item.press("ArrowRight");
    }
}

async function capture(page, artifacts, referenceImages, name) {
    fs.mkdirSync(artifacts, { recursive: true });
    const artifactPath = path.join(artifacts, name);
    await page.screenshot({
        path: artifactPath,
        fullPage: true,
    });
    if (referenceImages) {
        fs.mkdirSync(referenceImages, { recursive: true });
        fs.copyFileSync(artifactPath, path.join(referenceImages, name));
    }
}

async function selectQuickPick(page, label) {
    const rows = page.locator(".quick-input-list .monaco-list-row");
    await rows.first().waitFor({ state: "visible", timeout: 30_000 });
    const row = rows.filter({ hasText: label });
    await row.first().waitFor({ state: "visible", timeout: 30_000 });
    await row.first().click();
}

async function waitForPod(page, podName) {
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
        const pod = page.getByRole("treeitem").filter({ hasText: podName });
        if (await pod.count()) {
            return pod.first();
        }
        const refresh = page.getByRole("button", { name: "Refresh Pods", exact: true });
        if (await refresh.count()) {
            await refresh.click();
        }
        await page.waitForTimeout(1_000);
    }
    throw new Error(`pod ${podName} did not appear in the tree within 120 seconds`);
}

function terminalTab(page, podName) {
    return page
        .locator(".tab")
        .filter({ hasText: "Rumpelpod:" })
        .filter({ hasText: podName })
        .filter({ hasText: "codex" });
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

async function login(page, url, password) {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const passwordInput = page.locator('input[name="password"]');
    if (await passwordInput.count()) {
        await passwordInput.fill(password);
        await page.keyboard.press("Enter");
    }
    await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
}

async function main() {
    const url = requiredEnvironment("RUMPELPOD_VSCODE_URL");
    const podName = requiredEnvironment("RUMPELPOD_VSCODE_POD");
    const createdPodName = requiredEnvironment("RUMPELPOD_VSCODE_CREATED_POD");
    const changedFile = requiredEnvironment("RUMPELPOD_VSCODE_CHANGED_FILE");
    const originalContent = requiredEnvironment("RUMPELPOD_VSCODE_ORIGINAL_CONTENT");
    const podContent = requiredEnvironment("RUMPELPOD_VSCODE_POD_CONTENT");
    const executablePath = requiredEnvironment("RUMPELPOD_CHROMIUM");
    const artifacts = requiredEnvironment("RUMPELPOD_VSCODE_ARTIFACTS");
    const password = requiredEnvironment("RUMPELPOD_VSCODE_PASSWORD");
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
        await login(page, url, password);
        await openRumpelpodView(page);

        const reviewPodBeforeCreation = await locatePodOrReportError(page, podName);
        await reviewPodBeforeCreation.waitFor({ state: "visible", timeout: 30_000 });
        await capture(page, artifacts, referenceImages, "01-pod-list.png");

        await reviewPodBeforeCreation.click();
        await terminalTab(page, podName).first().waitFor({ state: "visible", timeout: 30_000 });
        await page.locator(".monaco-diff-editor").last().waitFor({ state: "visible", timeout: 30_000 });

        const createPod = page.getByRole("button", { name: "Create Pod", exact: true });
        await createPod.waitFor({ state: "visible", timeout: 30_000 });
        await createPod.click();
        const agentPicks = page.locator(".quick-input-list .monaco-list-row");
        await agentPicks.first().waitFor({ state: "visible", timeout: 30_000 });
        const agentLabels = (await agentPicks.allTextContents()).join("\n");
        assert(agentLabels.includes("Claude Code"), `agent picker omitted Claude: ${agentLabels}`);
        assert(agentLabels.includes("Codex"), `agent picker omitted Codex: ${agentLabels}`);
        await capture(page, artifacts, referenceImages, "02-agent-picker.png");
        await selectQuickPick(page, "Codex");

        const podNameInput = page.locator(".quick-input-widget input");
        await podNameInput.waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await podNameInput.getAttribute("placeholder"),
            "feature-name",
            "pod creation did not advance to the name input",
        );
        await podNameInput.fill(createdPodName);
        await capture(page, artifacts, referenceImages, "03-pod-name.png");
        await page.keyboard.press("Enter");

        const createdTerminalTab = terminalTab(page, createdPodName);
        await createdTerminalTab.first().waitFor({ state: "visible", timeout: 30_000 });
        const createdTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await createdTerminal.waitFor({ state: "visible", timeout: 30_000 });

        const startingStatus = page
            .locator(".monaco-editor:visible .view-lines")
            .filter({ hasText: `${createdPodName} is starting` });
        await startingStatus.first().waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await page.locator(".monaco-diff-editor:visible").count(),
            0,
            "creating a pod left the previous pod's diff visible",
        );
        await waitForCodexPrompt(page, createdTerminal);

        const createdPod = await waitForPod(page, createdPodName);
        await createdPod.waitFor({ state: "visible", timeout: 30_000 });
        const createdPodLabel = (await createdPod.textContent()) || "";
        assert(
            createdPodLabel.includes("Codex - running"),
            `created pod omitted its agent or running status: ${createdPodLabel}`,
        );
        const listedPodLabels = await page.getByRole("treeitem").allTextContents();
        assert(
            listedPodLabels.some((label) => label.includes(podName)),
            `existing pod disappeared after creation: ${JSON.stringify(listedPodLabels)}`,
        );
        assert(
            listedPodLabels.some((label) => label.includes(createdPodName)),
            `created pod was not listed: ${JSON.stringify(listedPodLabels)}`,
        );
        await capture(page, artifacts, referenceImages, "04-created-pod.png");

        const pod = await locatePodOrReportError(page, podName);
        await pod.click();
        const reviewTerminalTab = terminalTab(page, podName);
        await reviewTerminalTab.first().waitFor({ state: "visible", timeout: 30_000 });
        await page
            .locator(".terminal-editor .xterm")
            .first()
            .waitFor({ state: "visible", timeout: 30_000 });

        await expandTreeItem(pod);

        const file = await locateTreeItem(page, changedFile);
        await file.click();

        const diffEditor = page.locator(".monaco-diff-editor").last();
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
        const editorText = await diffEditor.locator(".view-lines").allTextContents();
        const rendered = editorText.join("\n").replace(/\u00a0/g, " ");
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

        const terminal = page.locator(".terminal-editor .xterm:visible").first();
        const terminalBounds = await terminal.boundingBox();
        const diffBounds = await diffEditor.boundingBox();
        assert(terminalBounds, "the agent terminal had no visible bounds");
        assert(diffBounds, "the review diff had no visible bounds");
        assert(
            terminalBounds.x < diffBounds.x,
            `agent terminal was not left of the review diff: ${JSON.stringify({ terminalBounds, diffBounds })}`,
        );
        assert(
            terminalBounds.y < diffBounds.y + diffBounds.height &&
                diffBounds.y < terminalBounds.y + terminalBounds.height,
            `agent terminal and review diff were not visible together: ${JSON.stringify({ terminalBounds, diffBounds })}`,
        );
        assert.equal(await createdTerminalTab.count(), 1, "created pod had duplicate terminals");
        assert.equal(await reviewTerminalTab.count(), 1, "review pod had duplicate terminals");
        const assignedReviewPod = await locatePodOrReportError(page, podName);
        const assignedReviewLabel = (await assignedReviewPod.textContent()) || "";
        assert(
            assignedReviewLabel.includes("Codex - running"),
            `opened pod kept a stale agent label: ${assignedReviewLabel}`,
        );
        await capture(page, artifacts, referenceImages, "05-review.png");

        await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 });
        await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
        await openRumpelpodView(page);
        await terminalTab(page, createdPodName).first().waitFor({ state: "visible", timeout: 30_000 });
        await terminalTab(page, podName).first().waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await terminalTab(page, createdPodName).count(),
            1,
            "created pod terminal was duplicated after reload",
        );
        assert.equal(
            await terminalTab(page, podName).count(),
            1,
            "review pod terminal was duplicated after reload",
        );
        const restoredCreatedPod = await locatePodOrReportError(page, createdPodName);
        await restoredCreatedPod.click();
        await terminalTab(page, createdPodName).first().waitFor({ state: "visible", timeout: 30_000 });
        assert.equal(
            await terminalTab(page, createdPodName).count(),
            1,
            "switching to a restored pod created another terminal",
        );
        const restoredTerminal = page.locator(".terminal-editor .xterm:visible").first();
        await restoredTerminal.waitFor({ state: "visible", timeout: 30_000 });
        await waitForCodexPrompt(page, restoredTerminal, false);
        await page
            .locator(".monaco-editor:visible .view-lines")
            .filter({ hasText: `No changes to review for ${createdPodName}` })
            .first()
            .waitFor({ state: "visible", timeout: 30_000 });
        await capture(page, artifacts, referenceImages, "06-restored-terminal.png");
        assert.equal(
            browserErrors.length,
            0,
            `browser page errors occurred: ${browserErrors.map((error) => error.message).join("; ")}`,
        );
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
