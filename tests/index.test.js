import test from "tape";
import { getWorkflowIdFromFile, getWorkflowIdFromRunId } from "../lib/index.js";
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
