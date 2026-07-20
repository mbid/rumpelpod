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

async function main() {
    const url = requiredEnvironment("RUMPELPOD_VSCODE_URL");
    const podName = requiredEnvironment("RUMPELPOD_VSCODE_POD");
    const changedFile = requiredEnvironment("RUMPELPOD_VSCODE_CHANGED_FILE");
    const originalContent = requiredEnvironment("RUMPELPOD_VSCODE_ORIGINAL_CONTENT");
    const podContent = requiredEnvironment("RUMPELPOD_VSCODE_POD_CONTENT");
    const executablePath = requiredEnvironment("RUMPELPOD_CHROMIUM");
    const artifacts = requiredEnvironment("RUMPELPOD_VSCODE_ARTIFACTS");

    const browser = await chromium.launch({
        executablePath,
        headless: true,
        args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    page.on("console", (message) => {
        process.stderr.write(`[BROWSER ${message.type()}] ${message.text()}\n`);
    });
    page.on("pageerror", (error) => {
        process.stderr.write(`[BROWSER ERROR] ${error.stack || error.message}\n`);
    });

    try {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
        await page.locator(".monaco-workbench").waitFor({ state: "visible", timeout: 60_000 });
        await openRumpelpodView(page);

        const pod = await locateTreeItem(page, podName);
        await expandTreeItem(pod);

        const file = await locateTreeItem(page, changedFile);
        await file.click();

        const diffEditor = page.locator(".monaco-diff-editor").last();
        await diffEditor.waitFor({ state: "visible", timeout: 30_000 });
        const editorText = await diffEditor.locator(".view-lines").allTextContents();
        const rendered = editorText.join("\n");
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
        await browser.close();
    }
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exitCode = 1;
});
