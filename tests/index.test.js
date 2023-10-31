import { test } from "uvu";
import * as assert from "uvu/assert";
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

test("getWorkflowFromFile", async () => {
	const workflow = await getWorkflowFromFile(testClient, testRepo, "main.yml");

	assert.equal(workflow.id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowFromFile NotFound", async () => {
	try {
		await getWorkflowFromFile(testClient, testRepo, "failure");
		assert.unreachable("Did not throw expected error.");
	} catch (e) {
		assert.ok(
			e.message.match(/Could not find workflow/g),
			"Throws friendly error if workflow is not found"
		);
	}
});

test("getWorkflowFromRunId", async () => {
	const workflow = await getWorkflowFromRunId(testClient, testRepo, 162490580);

	assert.equal(workflow.id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowRunForCommit for push commit run", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/master"
	);

	assert.equal(commitRun.id, 162658683, "Correct run ID is returned");
	assert.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit for pull_request commit run (e.g. PR into PR)", async () => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		1827281,
		"4f7618a381231923ebd37932ce43f588b74d3eb0",
		"get-workflow-run"
	);

	assert.equal(commitRun.id, 163536999, "Correct run ID is returned");
	assert.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit with bad ref", async () => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testRepo,
		1827281,
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
		1827281,
		"9c81cadeed9dfc5a2ae8555046b323bf3be712cf",
		"refs/heads/master"
	);

	assert.not.ok(commitRun, "Returns undefined if not found on branch");
	assert.ok(lkgRun, "Returns LKG run event if commit can't be found");
});

test("getArtifact", async () => {
	const artifact = await getArtifact(
		testClient,
		testRepo,
		163653716,
		"test-artifact.txt"
	);

	assert.equal(artifact.id, 10721454, "Returns  if not found on branch");
});

test("getArtifact not found", async () => {
	const artifact = await getArtifact(
		testClient,
		testRepo,
		163653716,
		"not-found.txt"
	);

	assert.equal(
		artifact,
		undefined,
		"Returns undefined if artifact is not found"
	);
});

test.run();
