import core from "@actions/core";
import github from "@actions/github";
import {
	getWorkflowIdFromFile,
	getWorkflowIdFromRunId,
	getWorkflowRunForCommit,
} from "./lib";

/**
 * @param {GitHubClient} octokit
 * @param {GitHubContext} context
 * @param {Inputs} inputs
 */
async function run(octokit, context, inputs) {
	core.debug("Inputs: " + JSON.stringify(inputs, null, 2));
	core.debug("Context: " + JSON.stringify(context, undefined, 2));

	// 1. Determine workflow
	/** @type {number} */
	let workflowId;
	if (inputs.workflow) {
		core.info(
			`Trying to get workflow ID from given file: ${inputs.workflow}...`
		);
		workflowId = await getWorkflowIdFromFile(octokit, context, inputs.workflow);
	} else {
		core.info(
			`Trying to get workflow ID from current workflow run: ${context.runId}...`
		);
		workflowId = await getWorkflowIdFromRunId(octokit, context, context.runId);
	}
	core.info(`Resolved to workflow ID: ${workflowId}`);

	// 2. Determine base commit
	/** @type {string} */
	let baseCommit, baseRef;
	if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;
		core.info(`Previous commit before push was ${baseCommit}.`);
	} else if (context.eventName == "pull_request") {
		baseCommit = context.payload.pull_request.base.sha;
		baseRef = context.payload.pull_request.base.ref;
		core.info(`Base commit of pull request is ${baseCommit}.`);
	} else {
		throw new Error(
			`Unsupported eventName in github.context: ${context.eventName}`
		);
	}

	// 3. Determine most recent workflow run for commit
	const workflowRun = await getWorkflowRunForCommit(
		octokit,
		context.repo,
		workflowId,
		baseCommit,
		baseRef
	);

	if (!workflowRun) {
		const params = JSON.stringify({ workflowId, baseCommit, baseRef });
		throw new Error(`Could not find workflow run for ${params}`);
	}

	// 4. Download artifact for base workflow
}

(async () => {
	try {
		const token = core.getInput("github_token", { required: true });
		const workflow = core.getInput("workflow", { required: false });
		const artifact = core.getInput("artifact", { required: true });
		const path = core.getInput("path", { required: false });

		const octokit = github.getOctokit(token);
		await run(octokit, github.context, {
			workflow,
			artifact,
			path,
		});
	} catch (e) {
		core.setFailed(e.message);
	}
})();
