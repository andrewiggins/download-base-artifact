const test = require("tape");
const {
	getWorkflowFromFile,
	getWorkflowFromRunId,
	getWorkflowRunForCommit,
	getArtifact,
} = require("../lib/index.js");

// Mostly copied from: https://github.com/actions/toolkit/blob/cee7d92d1d02e3107c9b1387b9690b89096b67be/packages/github/src/utils.ts#L12
// Copied from there to allow for un-authed requests for local testing

const github = require("@actions/github");
const httpClient = require("@actions/http-client");
const octokit = require("@octokit/core");
const endpointPlugin = require("@octokit/plugin-rest-endpoint-methods");
const paginatePlugin = require("@octokit/plugin-paginate-rest");

const baseUrl = "https://api.github.com";
const hc = new httpClient.HttpClient();
const agent = hc.getAgent(baseUrl);

const defaults = {
	baseUrl,
	request: {
		agent,
	},
};

function getTestClient() {
	if (process.env.GITHUB_TOKEN) {
		return github.getOctokit(process.env.GITHUB_TOKEN);
	} else {
		const GitHub = octokit.Octokit.plugin(
			endpointPlugin.restEndpointMethods,
			paginatePlugin.paginateRest
		).defaults(defaults);

		return new GitHub();
	}
}

const testClient = getTestClient();

/** @type {GitHubContext} */
const testContext = {
	repo: {
		owner: "andrewiggins",
		repo: "download-base-artifact",
	},
};

test("getWorkflowFromFile", async (t) => {
	const workflow = await getWorkflowFromFile(
		testClient,
		testContext,
		"main.yml"
	);

	t.equal(workflow.id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowFromFile NotFound", async (t) => {
	try {
		await getWorkflowFromFile(testClient, testContext, "failure");
		t.fail("Do not throw expected error.");
	} catch (e) {
		t.match(
			e.message,
			/Could not find workflow/g,
			"Throws friendly error if workflow is not found"
		);
	}
});

test("getWorkflowFromRunId", async (t) => {
	const workflow = await getWorkflowFromRunId(
		testClient,
		testContext,
		162490580
	);

	t.equal(workflow.id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowRunForCommit for push commit run", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/master"
	);

	t.equal(commitRun.id, 162658683, "Correct run ID is returned");
	t.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit for pull_request commit run (e.g. PR into PR)", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"4f7618a381231923ebd37932ce43f588b74d3eb0",
		"get-workflow-run"
	);

	t.equal(commitRun.id, 163536999, "Correct run ID is returned");
	t.ok(lkgRun, "Returns a valid lkg run");
});

test("getWorkflowRunForCommit with bad ref", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/fake-branch"
	);

	t.notOk(commitRun, "Returns undefined for commitRun if ref doesn't exist");
	t.notOk(lkgRun, "Returns undefined for lkgRun if ref doesn't exist");
});

test("getWorkflowRunForCommit with unknown commit", async (t) => {
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"9c81cadeed9dfc5a2ae8555046b323bf3be712cf",
		"refs/heads/master"
	);

	t.notOk(commitRun, "Returns undefined if not found on branch");
	t.ok(lkgRun, "Returns LKG run event if commit can't be found");
});

test("getArtifact", async (t) => {
	const artifact = await getArtifact(
		testClient,
		testContext.repo,
		163653716,
		"test-artifact.txt"
	);

	t.equal(artifact.id, 10721454, "Returns  if not found on branch");
});

test("getArtifact not found", async (t) => {
	const artifact = await getArtifact(
		testClient,
		testContext.repo,
		163653716,
		"not-found.txt"
	);

	t.equal(artifact, undefined, "Returns undefined if artifact is not found");
});
