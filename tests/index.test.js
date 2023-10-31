import { test } from "uvu";
import * as assert from "uvu/assert";
import * as nodeAssert from "node:assert/strict";
import fs from "fs";
import path from "path";
import {
	getWorkflowFromFile,
	getWorkflowFromRunId,
	getWorkflowRunForCommit,
	getArtifact,
} from "../index.js";

// Mostly copied from: https://github.com/actions/toolkit/blob/cee7d92d1d02e3107c9b1387b9690b89096b67be/packages/github/src/utils.ts#L12
// Copied from there to allow for un-authed requests for local testing

import { getOctokit } from "@actions/github";
import { HttpClient } from "@actions/http-client";
import { Octokit } from "@octokit/core";
import { restEndpointMethods } from "@octokit/plugin-rest-endpoint-methods";
import { paginateRest } from "@octokit/plugin-paginate-rest";

const __dirname = path.dirname(new URL(import.meta.url).pathname);
/** @type {(...args: string[]) => string} */
const p = (...args) => path.join(__dirname, "..", ...args);
const tokenPath = p(".github_token");

const baseUrl = "https://api.github.com";
const hc = new HttpClient();
const agent = hc.getAgent(baseUrl);

const defaults = {
	baseUrl,
	request: {
		agent,
	},
};

function getTestClient() {
	if (process.env.GITHUB_TOKEN) {
		return getOctokit(process.env.GITHUB_TOKEN);
	} else {
		if (fs.existsSync(tokenPath)) {
			return getOctokit(fs.readFileSync(tokenPath, "utf8").trim());
		}

		const GitHub = Octokit.plugin(restEndpointMethods, paginateRest).defaults(
			defaults
		);

		return new GitHub();
	}
}

const testClient = getTestClient();

/** @type {import('../index.js').GitHubRepo} */
const testRepo = {
	owner: "andrewiggins",
	repo: "download-base-artifact",
};

const workflowId = 1827281;
const runId = 3310300652;
const commitSha = "6e60998db346a1acaee4b470b4142d00dfc979ee";
const gitRef = "refs/heads/master";
const artifactName = "test-artifact.txt";
const artifactId = 408992374;

const prBranch = "upgrade-deps-and-node16";
const prRunId = 3310272485;
const prSha = "12d4e33eeeb5afb2d99cea6dfa1f6b1ad1caff17";

test("getWorkflowFromFile", async () => {
	const workflow = await getWorkflowFromFile(testClient, testRepo, "main.yml");
	assert.equal(workflow.id, workflowId, "Correct workflow ID is returned");
});

test("getWorkflowFromFile NotFound", async () => {
	await nodeAssert.rejects(
		() => getWorkflowFromFile(testClient, testRepo, "failure"),
		/Could not find workflow/g,
		"Expected getWorkflowFromFile to Throw friendly error if workflow is not found"
	);
});

test("getWorkflowFromRunId", async () => {
	const workflow = await getWorkflowFromRunId(testClient, testRepo, runId);
	assert.equal(workflow.id, workflowId, "Correct workflow ID is returned");
});

test("getWorkflowRunForCommit for push commit run", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		workflowId,
		commitSha,
		gitRef
	);

	assert.equal(commitRun.id, runId, "Correct run ID is returned");
	assert.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit for pull_request commit run (e.g. PR into PR)", async () => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		1827281,
		prSha,
		prBranch
	);

	assert.equal(commitRun.id, prRunId, "Correct run ID is returned");
	assert.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit with bad ref", async () => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		workflowId,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/fake-branch"
	);

	assert.not.ok(
		commitRun,
		"Returns undefined for commitRun if ref doesn't exist"
	);
	assert.not.ok(lkgRun, "Returns undefined for lkgRun if ref doesn't exist");
});

test("getWorkflowRunForCommit with unknown commit", async () => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		workflowId,
		"9c81cadeed9dfc5a2ae8555046b323bf3be712cf",
		gitRef
	);

	assert.not.ok(commitRun, "Returns undefined if not found on branch");
	assert.ok(lkgRun, "Returns LKG run event if commit can't be found");
});

test("getArtifact", async () => {
	const artifact = await getArtifact(testClient, testRepo, runId, artifactName);
	assert.equal(artifact.id, artifactId);
});

test("getArtifact not found", async () => {
	await nodeAssert.rejects(
		() => getArtifact(testClient, testRepo, 163653716, "not-found.txt"),
		/Not Found/g,
		"Expected getArtifact to reject if artifact not found"
	);
});

test.run();
