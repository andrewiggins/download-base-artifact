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

const defaultLogger = {
	warn(getMsg) {
		console.warn(getMsg);
	},
	info(getMsg) {
		console.log(getMsg);
	},
	debug() {},
};

/**
 * @typedef {ReturnType<typeof github.getOctokit>} GitHubActionClient
 * @typedef {{ workflow?: string; artifact: string; path?: string; }} Inputs
 * @typedef {{ warn(msg: string): void; info(msg: string): void; debug(getMsg: () => string): void; }} Logger
 *
 * @param {GitHubActionClient} octokit
 * @param {typeof github.context} context
 * @param {Inputs} inputs
 * @param {Logger} [log]
 */
async function run(octokit, context, inputs, log = defaultLogger) {
	const repo = context.repo;

	// 1. Determine workflow
	/** @type {WorkflowData} */
	let workflow;
	if (inputs.workflow) {
		log.info(`Trying to get workflow matching "${inputs.workflow}"...`);
		workflow = await getWorkflowFromFile(octokit, repo, inputs.workflow);
	} else {
		log.info(`Trying to get workflow of current run (id: ${context.runId})...`);
		workflow = await getWorkflowFromRunId(octokit, repo, context.runId);
	}

	log.debug(() => `Workflow: ${JSON.stringify(workflow, null, 2)}`);
	log.info(`Resolved to "${workflow.name}" (id: ${workflow.id})`);

	// 2. Determine base commit
	let baseCommit, baseRef;
	if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;

		log.info(`Ref of push is ${baseRef}`);
		log.info(`Previous commit before push is ${baseCommit}`);
	} else if (context.eventName == "pull_request") {
		baseCommit = context.payload.pull_request.base.sha;
		baseRef = context.payload.pull_request.base.ref;

		log.info(`Base ref of pull request is ${baseRef}`);
		log.info(`Base commit of pull request is ${baseCommit}`);
	} else {
		throw new Error(
			`Unsupported eventName in github.context: ${context.eventName}`
		);
	}

	// 3. Determine most recent workflow run for commit
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		octokit,
		repo,
		workflow.id,
		baseCommit,
		baseRef
	);

	log.debug(() => `Commit Run: ${JSON.stringify(commitRun, null, 2)}`);
	log.debug(() => `LKG Run: ${JSON.stringify(lkgRun, null, 2)}`);

	let workflowRun,
		warningMessage = "";
	if (commitRun && commitRun.conclusion == "success") {
		workflowRun = commitRun;
	} else {
		if (!commitRun) {
			warningMessage += `Could not find workflow run for ${baseCommit}.`;
		} else if (commitRun.conclusion !== "success") {
			warningMessage += `Workflow run for ${baseCommit} (${workflow.name}#${commitRun.run_number}) was not successful. Conclusion was "${commitRun.conclusion}".`;
		}

		if (lkgRun) {
			warningMessage += ` Using last successful run for ${baseRef}: ${workflow.name}#${lkgRun.run_number} (id: ${lkgRun.id})`;
			workflowRun = lkgRun;
		} else {
			warningMessage += ` Could not find any successful workflow run for ${baseRef} to fall back to.`;
		}
	}

	if (warningMessage !== "") {
		log.warn(warningMessage);
	}

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
	log.info(
		`Using ${workflowRunName} (id: ${workflowRun.id}) as base workflow run`
	);

	// 4. Download artifact for base workflow
	const artifact = await getArtifact(
		octokit,
		repo,
		workflowRun.id,
		inputs.artifact
	);

	log.debug(() => "Artifact: " + JSON.stringify(artifact, null, 2));
	log.info(`Located artifact "${artifact.name}" (id: ${artifact.id})`);

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
	log.info(`Downloading artifact ${artifact.name}.zip (${size})...`);
	const zip = await octokit.actions.downloadArtifact({
		...repo,
		artifact_id: artifact.id,
		archive_format: "zip",
	});

	log.info(`Extracting ${artifact.name}.zip...`);
	const adm = new AdmZip(Buffer.from(zip.data));
	adm.getEntries().forEach((entry) => {
		const action = entry.isDirectory ? "creating" : "inflating";
		const filepath = path.join(inputs.path, entry.entryName);
		log.info(`  ${action}: ${filepath}`);
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
		const inputs = { workflow, artifact, path };

		core.debug("Inputs: " + JSON.stringify(inputs, null, 2));
		core.debug("Context: " + JSON.stringify(github.context, undefined, 2));

		const actionLogger = {
			warn(msg) {
				core.warning(msg);
			},
			info(msg) {
				core.info(msg);
			},
			debug(getMsg) {
				core.debug(getMsg());
			},
		};

		await run(octokit, github.context, inputs, actionLogger);
	} catch (e) {
		core.setFailed(e.message);
	}
})();
