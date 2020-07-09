const core = require("@actions/core");
const github = require("@actions/github");
const {
	getWorkflowFromFile,
	getWorkflowFromRunId,
	getWorkflowRunForCommit,
} = require("./lib");

/**
 * @param {GitHubClient} octokit
 * @param {GitHubContext} context
 * @param {Inputs} inputs
 */
async function run(octokit, context, inputs) {
	core.debug("Inputs: " + JSON.stringify(inputs, null, 2));
	core.debug("Context: " + JSON.stringify(context, undefined, 2));

	// 1. Determine workflow
	/** @type {WorkflowData} */
	let workflow;
	if (inputs.workflow) {
		core.info(`Trying to get workflow from given file: ${inputs.workflow}...`);
		workflow = await getWorkflowFromFile(octokit, context, inputs.workflow);
	} else {
		core.info(
			`Trying to get workflow from current workflow run (id: ${context.runId})...`
		);
		workflow = await getWorkflowFromRunId(octokit, context, context.runId);
	}
	core.info(`Resolved to workflow "${workflow.name}" (id: ${workflow.id}).`);

	// 2. Determine base commit
	/** @type {string} */
	let baseCommit, baseRef;
	if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;

		core.info(`Ref of push is ${baseRef}.`);
		core.info(`Previous commit before push is ${baseCommit}.`);
	} else if (context.eventName == "pull_request") {
		baseCommit = context.payload.pull_request.base.sha;
		baseRef = context.payload.pull_request.base.ref;

		core.info(`Base ref of pull request is ${baseRef}.`);
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
		workflow.id,
		baseCommit,
		baseRef
	);

	if (!workflowRun) {
		const params = JSON.stringify({
			workflowId: workflow.id,
			baseCommit,
			baseRef,
			status: "success",
		});
		throw new Error(`Could not find workflow run matching ${params}`);
	}

	core.info(
		`Base workflow run: ${workflow.name}#${workflowRun.run_number} (id: ${workflowRun.id}).`
	);

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
