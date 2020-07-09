import test from "tape";
import {
	getWorkflowIdFromFile,
	getWorkflowIdFromRunId,
	getWorkflowRunForCommit,
} from "../lib/index.js";
import { getTestClient } from "./utils.js";

/** @type {GitHubContext} */
const testContext = {
	repo: {
		owner: "andrewiggins",
		repo: "download-base-artifact",
	},
};

const testClient = getTestClient();

test("getWorkflowIdFromFile", async (t) => {
	const id = await getWorkflowIdFromFile(testClient, testContext, "main.yml");
	t.equal(id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowIdFromFile NotFound", async (t) => {
	try {
		await getWorkflowIdFromFile(testClient, testContext, "failure");
		t.fail("Do not throw expected error.");
	} catch (e) {
		t.match(
			e.message,
			/Could not find workflow/g,
			"Throws friendly error if workflow is not found"
		);
	}
});

test("getWorkflowIdFromRunId", async (t) => {
	const id = await getWorkflowIdFromRunId(testClient, testContext, 162490580);
	t.equal(id, 1827281, "Correct workflow ID is returned");
});

test("getWorkflowRunForCommit for push", async (t) => {
	const res = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce"
	);

	t.equal(res.id, 162658683, "Correct run ID is returned");
});

test.skip("getWorkflowRunForCommit for pull_request", async (t) => {
	const res = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		""
	);

	t.equal(res.id, 162658683, "Correct run ID is returned");
});

test("getWorkflowRunForCommit with baseRef", async (t) => {
	const res = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/master"
	);

	t.equal(res.id, 162658683, "Correct run ID is returned");
});

test("getWorkflowRunForCommit with bad ref", async (t) => {
	const res = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"8c81cadeed9dfc5a2ae8555046b323bf3be712ce",
		"refs/heads/fake-branch"
	);

	t.equal(res, undefined, "Returns undefined if not found on branch");
});

test("getWorkflowRunForCommit with unknown commit", async (t) => {
	const res = await getWorkflowRunForCommit(
		testClient,
		testContext.repo,
		1827281,
		"9c81cadeed9dfc5a2ae8555046b323bf3be712cf"
	);

	t.equal(res, undefined, "Returns undefined if not found on branch");
});
