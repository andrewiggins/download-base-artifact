const path = require("path");
const { mkdir } = require("fs").promises;
const core = require("@actions/core");
const github = require("@actions/github");
const prettyBytes = require("pretty-bytes");
const AdmZip = require("adm-zip");
const {
	getWorkflowFromFile,
	getWorkflowFromRunId,
	getWorkflowRunForCommit,
	getArtifact,
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

	core.debug(`Workflow: ${JSON.stringify(workflow, null, 2)}`);
	core.info(`Resolved to workflow "${workflow.name}" (id: ${workflow.id})`);

	// 2. Determine base commit
	/** @type {string} */
	let baseCommit, baseRef;
	if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;

		core.info(`Ref of push is ${baseRef}`);
		core.info(`Previous commit before push is ${baseCommit}`);
	} else if (context.eventName == "pull_request") {
		baseCommit = context.payload.pull_request.base.sha;
		baseRef = context.payload.pull_request.base.ref;

		core.info(`Base ref of pull request is ${baseRef}`);
		core.info(`Base commit of pull request is ${baseCommit}`);
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

	core.debug(`Workflow Run: ${JSON.stringify(workflowRun, null, 2)}`);

	if (!workflowRun) {
		const params = JSON.stringify({
			workflowId: workflow.id,
			baseCommit,
			baseRef,
			status: "success",
		});
		throw new Error(`Could not find workflow run matching ${params}`);
	}

	const workflowRunName = `${workflow.name}#${workflowRun.run_number}`;
	core.info(`Base workflow run: ${workflowRunName} (id: ${workflowRun.id})`);

	// 4. Download artifact for base workflow
	const artifact = await getArtifact(
		octokit,
		context.repo,
		workflowRun.id,
		inputs.artifact
	);

	core.debug("Artifact: " + JSON.stringify(artifact, null, 2));
	core.info(`Located artifact "${artifact.name}" (id: ${artifact.id})`);

	if (artifact.expired) {
		throw new Error(
			`Artifact "${artifact.name}" for workflow run ${workflowRunName} is expired. Please re-run workflow to regenerate artifacts.`
		);
	}

	if (!inputs.path) {
		inputs.path = ".";
	}

	await mkdir(inputs.path, { recursive: true });

	const size = prettyBytes(artifact.size_in_bytes);
	core.info(`Downloading artifact ${artifact.name}.zip (${size})...`);
	const zip = await octokit.actions.downloadArtifact({
		...context.repo,
		artifact_id: artifact.id,
		archive_format: "zip",
	});

	core.info(`Extracting ${artifact.name}.zip...`);
	const adm = new AdmZip(Buffer.from(zip.data));
	adm.getEntries().forEach((entry) => {
		const action = entry.isDirectory ? "creating" : "inflating";
		const filepath = path.join(inputs.path, entry.entryName);
		core.info(`  ${action}: ${filepath}`);
	});

	adm.extractAllTo(inputs.path, true);
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
